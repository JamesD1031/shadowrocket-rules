#!/usr/bin/env python3
"""Merge public upstream/rules with a private local Shadowrocket export."""
import argparse
import json
import os
import re
from collections import OrderedDict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BEGIN = '# BEGIN SHADOWROCKET-CONFIGS MANAGED RULES'
END = '# END SHADOWROCKET-CONFIGS MANAGED RULES'


def private_output(path):
    path = Path(path).expanduser().resolve()
    if path.is_relative_to(ROOT):
        raise ValueError('Private/generated output must be outside this repository')
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    return path


def write_private(path, text):
    path = private_output(path)
    # O_EXCL temporary file prevents overwriting a symlink or opening with a lax mode.
    temp = path.with_name(path.name + f'.tmp-{os.getpid()}')
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            f.write(text)
        os.replace(temp, path)
    finally:
        if temp.exists():
            temp.unlink()


def parse(text):
    result = OrderedDict()
    section = None
    for line in text.splitlines():
        heading = re.fullmatch(r'\s*\[([^]]+)\]\s*', line)
        if heading:
            section = heading[1].casefold()
            result.setdefault(section, [])
        elif section is not None:
            result[section].append(line)
    return result


def active(lines):
    return [s.strip() for s in lines if s.strip() and not s.lstrip().startswith(('#', ';'))]


def kv(lines):
    result = OrderedDict()
    for line in active(lines):
        if '=' not in line:
            raise ValueError('Invalid key/value configuration line')
        key, value = map(str.strip, line.split('=', 1))
        result[key.casefold()] = (key, value)
    return result


def merged_values(upstream, local, previous=None):
    values = kv(upstream)
    old = kv(previous or [])
    for lower, entry in kv(local).items():
        # An unchanged old default follows the new upstream; explicit overrides survive.
        if lower in old and old[lower][1] == entry[1]:
            continue
        values[lower] = entry
    return [f'{key} = {value}' for key, value in values.values()]


def aliases_for(manifest):
    return {k.casefold(): v for k, v in manifest['policy_aliases'].items()}


def rename_groups(lines, aliases):
    return [f'{aliases.get(key.casefold(), key)} = {value}' for key, value in kv(lines).values()]


def rule_with_policy(line, policy):
    parts = [p.strip() for p in line.split(',')]
    if len(parts) < 2 or parts[0] not in {'DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD', 'DOMAIN-WILDCARD', 'IP-CIDR', 'IP-CIDR6'}:
        raise ValueError('Unsupported personal rule: ' + line)
    if any(p not in {'no-resolve'} for p in parts[2:]):
        raise ValueError('Rule lists contain predicates only, never policies or URLs')
    return ','.join(parts[:2] + [policy] + parts[2:])


def canonical_rule(line):
    return re.sub(r'\s+', '', line).casefold()


def remap_rule(line, aliases):
    parts = [p.strip() for p in line.split(',')]
    index = 1 if parts[0].upper() == 'FINAL' else 2
    if len(parts) > index:
        parts[index] = aliases.get(parts[index].casefold(), parts[index])
    return ','.join(parts)


def build(upstream_text, local_text, manifest, root=ROOT, previous_text=None, initial=False):
    upstream, local = parse(upstream_text), parse(local_text)
    previous = parse(previous_text) if previous_text else {}
    aliases = aliases_for(manifest)
    if 'rule' not in upstream or 'proxy group' not in upstream:
        raise ValueError('Upstream is not a complete Shadowrocket group configuration')
    if not initial:
        local_rules = '\n'.join(local.get('rule', []))
        if BEGIN not in local_rules or END not in local_rules:
            raise ValueError('First migration needs --initial-migration after reviewing all local custom rules')
        unmanaged = local_rules.split(BEGIN, 1)[0] + local_rules.split(END, 1)[1]
        expected = {canonical_rule(remap_rule(s, aliases)) for s in active(previous.get('rule', upstream['rule']))}
        unexpected = [s for s in active(unmanaged.splitlines()) if canonical_rule(s) not in expected]
        if unexpected:
            raise ValueError('Unmanaged local rules exist; move them into rules/*.list before rebuilding')

    result = OrderedDict()
    result['general'] = merged_values(upstream.get('general', []), local.get('general', []), previous.get('general'))
    result['general'] = [s for s in result['general'] if s.split('=', 1)[0].strip().casefold() != 'update-url']
    result['proxy'] = list(local.get('proxy', []))  # Private node definitions never come from the repository.
    up_groups = rename_groups(upstream['proxy group'], aliases)
    local_groups = [s for s in local.get('proxy group', []) if not any(s.split('=', 1)[0].strip().casefold() == k for k in aliases)]
    # Facebook(Meta) is the personal replacement for upstream Facebook; 谷歌AI is intentionally merged.
    old_groups = rename_groups(previous.get('proxy group', []), aliases)
    result['proxy group'] = merged_values(up_groups, local_groups, old_groups)
    groups = kv(result['proxy group'])
    for policy, node in manifest['preferred_nodes'].items():
        key = policy.casefold()
        if key not in groups:
            raise ValueError('Preferred policy missing: ' + policy)
        name, value = groups[key]
        fields = value.split(',')
        fields = [s for s in fields if not s.startswith('policy-select-name=')]
        if not any(s.casefold() == node.casefold() for s in fields[1:]):
            fields.insert(1, node)
        groups[key] = (name, ','.join(fields + ['policy-select-name=' + node]))
    result['proxy group'] = [f'{k} = {v}' for k, v in groups.values()]

    rules = [BEGIN]
    for spec in manifest['rules']:
        path = (Path(root) / spec['file']).resolve()
        if not path.is_relative_to(Path(root).resolve()):
            raise ValueError('Rule file outside repository')
        rules.append('# ' + spec['file'] + ' -> ' + spec['policy'])
        rules.extend(rule_with_policy(s, spec['policy']) for s in active(path.read_text().splitlines()))
    rules.append(END)
    rules.extend(remap_rule(s, aliases) for s in active(upstream['rule']))
    result['rule'] = rules
    result['host'] = merged_values(upstream.get('host', []), local.get('host', []), previous.get('host'))
    old_rewrites = set(active(previous.get('url rewrite', [])))
    personal_rewrites = [s for s in active(local.get('url rewrite', [])) if s not in old_rewrites]
    result['url rewrite'] = list(dict.fromkeys(active(upstream.get('url rewrite', [])) + personal_rewrites))
    if 'mitm' in local:
        result['mitm'] = local['mitm'][:]  # Certificate, enablement and interception scope stay local.
    for section, lines in local.items():
        if section not in result:
            result[section] = lines[:]

    known = set(groups) | {'direct', 'proxy', 'reject', 'reject-drop', 'reject-tinydrop'}
    known |= set(kv(result['proxy']))
    for line in active(result['rule']):
        fields = line.split(',')
        policy = fields[1] if fields[0] == 'FINAL' else fields[2]
        if policy.casefold() not in known:
            raise ValueError('Rule references undefined policy: ' + policy)
    titles = {'proxy group': 'Proxy Group', 'url rewrite': 'URL Rewrite', 'mitm': 'MITM'}
    text = '# Generated from JamesD1031/shadowrocket-configs; private local settings retained.\n'
    text += '\n\n'.join('[' + titles.get(s, s.title()) + ']\n' + '\n'.join(lines).strip() for s, lines in result.items()) + '\n'
    return text


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--local', type=Path, required=True, help='Fresh private full export, outside the repository')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--previous-upstream', type=Path)
    parser.add_argument('--initial-migration', action='store_true')
    args = parser.parse_args()
    if args.local.resolve().is_relative_to(ROOT):
        parser.error('Local export must be outside the repository')
    manifest = json.loads((ROOT / 'config/manifest.json').read_text())
    previous = args.previous_upstream.read_text() if args.previous_upstream else None
    text = build((ROOT / 'upstream/lazy_group.conf').read_text(), args.local.read_text(), manifest, previous_text=previous, initial=args.initial_migration)
    write_private(args.output, text)
    print('Built private configuration; validate and import with Shadowrocket native UI.')


if __name__ == '__main__':
    main()
