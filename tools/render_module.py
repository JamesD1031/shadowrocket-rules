#!/usr/bin/env python3
"""Render only public routing rules; never read a local export or application DB."""
import argparse
import hashlib
import json
import re
from pathlib import Path
from build import ROOT, active, aliases_for, canonical_rule, kv, parse, remap_rule, rule_with_policy


def render(root=ROOT):
    root = Path(root)
    manifest = json.loads((root / 'config/manifest.json').read_text())
    settings = json.loads((root / 'config/module.json').read_text())
    source = json.loads((root / 'upstream/source.json').read_text())
    raw = (root / 'upstream/lazy_group.conf').read_bytes()
    if hashlib.sha256(raw).hexdigest() != source['sha256']:
        raise ValueError('Upstream snapshot hash does not match source.json')
    upstream = parse(raw.decode('utf-8'))
    aliases = aliases_for(manifest)
    known = {s.casefold() for s in settings['local_policies']}
    known |= {'direct', 'proxy', 'reject', 'reject-drop', 'reject-tinydrop'}
    rules = []
    for item in manifest['rules']:
        path = (root / item['file']).resolve()
        if not path.is_relative_to((root / 'rules').resolve()) or path.suffix != '.list':
            raise ValueError('Personal rules must be .list files inside rules/')
        rules.extend(rule_with_policy(s, item['policy']) for s in active(path.read_text().splitlines()))
    rules.extend(remap_rule(s, aliases) for s in active(upstream['rule']))
    result = []
    seen = set()
    allowed = {'DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD', 'DOMAIN-WILDCARD', 'IP-CIDR', 'IP-CIDR6', 'IP-ASN', 'GEOIP', 'RULE-SET', 'FINAL'}
    for rule in rules:
        fields = [p.strip() for p in rule.split(',')]
        if fields[0] not in allowed:
            raise ValueError('Unsupported upstream rule type: ' + fields[0])
        if fields[0] == 'FINAL':
            if fields != ['FINAL', 'PROXY']:
                raise ValueError('Upstream final policy changed; review local fallback first')
            continue  # The local profile owns its catch-all policy.
        if len(fields) < 3 or fields[2].casefold() not in known:
            raise ValueError('Rule requires an unavailable local policy')
        if fields[0] == 'RULE-SET':
            if not re.fullmatch(r'https://raw\.githubusercontent\.com/[A-Za-z0-9_.%/-]+', fields[1]):
                raise ValueError('Remote rule-set URL is not an approved public Raw URL')
        canonical = canonical_rule(rule)
        if canonical not in seen:
            result.append(rule)
            seen.add(canonical)
    text = '#!name=James 云端分流规则\n#!desc=自动跟踪懒人规则；节点选择和证书保留在本机\n'
    text += '# Upstream commit: ' + source['commit'] + '\n\n[Rule]\n' + '\n'.join(result) + '\n'
    if any(s in text.casefold() for s in ('ca-p12', 'ca-passphrase', 'password=', 'authorization:', '[mitm]', '[proxy]', '[script]')):
        raise ValueError('Unexpected private or executable settings in public module')
    return text


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=ROOT / 'release/routing.module')
    args = parser.parse_args()
    text = render()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(text, encoding='utf-8')
    print('Validated public routing module:', len(active(parse(text)['rule'])), 'rules')


if __name__ == '__main__':
    main()
