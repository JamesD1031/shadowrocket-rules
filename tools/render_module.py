#!/usr/bin/env python3
"""Render only public routing rules; never read a local export or application DB."""
import argparse
import hashlib
import json
import re
from collections import OrderedDict
from pathlib import Path
from build import ROOT, active, aliases_for, canonical_rule, kv, parse, remap_rule, rule_with_policy


BASE_URL = 'https://raw.githubusercontent.com/JamesD1031/shadowrocket-rules/main/'


def expanded_rules(root=ROOT):
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
    return result


def rule_line(rule, title):
    if any(s in title for s in ('\n', '\r', '//')):
        raise ValueError('Invalid rule title')
    # Verified on the installed client: // is stored in config.remarks.
    # The installed client's rule list still uses the URL as its primary title.
    return rule + ' // ' + title


def bundle_plan(root=ROOT):
    root = Path(root)
    manifest = json.loads((root / 'config/manifest.json').read_text())
    catalog = json.loads((root / 'config/catalog.json').read_text())
    flat = expanded_rules(root)
    artifacts, entries, consumed = OrderedDict(), [], []
    seen = set()

    def bundle(ident, title, lines, policy):
        if not re.fullmatch(r'[a-z0-9-]+', ident):
            raise ValueError('Invalid public bundle identifier')
        predicates = []
        for line in lines:
            fields = line.split(',')
            if fields[2].casefold() != policy.casefold():
                raise ValueError('A bundle must have one policy')
            predicates.append(','.join(fields[:2] + fields[3:]))
        content = '# ' + title + '\n' + '\n'.join(predicates) + '\n'
        digest = hashlib.sha256(content.encode()).hexdigest()[:16]
        path = 'release/rules/' + ident + '-' + digest + '.list'
        artifacts[path] = content
        entries.append({'title': title, 'rule': 'RULE-SET,' + BASE_URL + path + ',' + policy,
                        'bundle': path, 'expanded': lines})

    for item in manifest['rules']:
        lines = []
        for predicate in active((root / item['file']).read_text().splitlines()):
            line = rule_with_policy(predicate, item['policy'])
            key = canonical_rule(line)
            if key not in seen:
                lines.append(line)
                consumed.append(line)
                seen.add(key)
        if lines:
            bundle(item['id'], item['title'], lines, item['policy'])
    if flat[:len(consumed)] != consumed:
        raise ValueError('Personal rule ordering changed while packing')
    remaining = flat[len(consumed):]
    index = 0
    while index < len(remaining):
        line = remaining[index]
        fields = line.split(',')
        if fields[0] == 'RULE-SET':
            title = catalog.get(fields[1], '上游服务 · ' + Path(fields[1]).stem)
            entries.append({'title': title, 'rule': line, 'expanded': [line]})
            index += 1
        elif fields[0] == 'GEOIP':
            entries.append({'title': '基础网络 · 中国 IP 直连', 'rule': line, 'expanded': [line]})
            index += 1
        else:
            policy = fields[2]
            lines = []
            while index < len(remaining):
                f = remaining[index].split(',')
                if f[0] in {'RULE-SET', 'GEOIP'} or f[2] != policy:
                    break
                lines.append(remaining[index]); index += 1
            if policy.casefold() == 'max':
                ident, title = 'max-extra', '影音 · Max 补充域名'
            else:
                ident, title = 'upstream-extra-' + str(index), '上游服务 · ' + policy + ' 补充规则'
            bundle(ident, title, lines, policy)
    if [line for entry in entries for line in entry['expanded']] != flat:
        raise ValueError('Packing changed rule matching order')
    return entries, artifacts


def render(root=ROOT):
    root = Path(root)
    source = json.loads((root / 'upstream/source.json').read_text())
    entries, _ = bundle_plan(root)
    text = '#!name=James 云端分流规则\n#!desc=分类规则集；中文名称；节点选择和证书保留在本机\n'
    text += '# Upstream commit: ' + source['commit'] + '\n\n[Rule]\n'
    text += '\n'.join(rule_line(entry['rule'], entry['title']) for entry in entries) + '\n'
    if any(s in text.casefold() for s in ('ca-p12', 'ca-passphrase', 'password=', 'authorization:', '[mitm]', '[proxy]', '[script]')):
        raise ValueError('Unexpected private or executable settings in public module')
    return text


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=ROOT / 'release/routing.module')
    args = parser.parse_args()
    text = render()
    entries, artifacts = bundle_plan()
    for name, content in artifacts.items():
        path = ROOT / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding='utf-8')
    index = [{'title': entry['title'], 'rule': entry['rule'],
              'bundle': entry.get('bundle'), 'expanded_count': len(entry['expanded'])} for entry in entries]
    (ROOT / 'release').mkdir(parents=True, exist_ok=True)
    (ROOT / 'release/catalog.json').write_text(json.dumps(index, ensure_ascii=False, indent=2) + '\n')
    overview = '# 分流规则分类清单\n\n小火箭的规则列表仍显示链接；本清单提供完整中文分类，纯文本配置中也保留相同备注。\n\n'
    overview += '| 顺序 | 分类名称 | 策略 | 内容 |\n| --- | --- | --- | --- |\n'
    for i, entry in enumerate(entries, 1):
        fields = entry['rule'].split(',')
        content = str(len(entry['expanded'])) + ' 条打包规则' if 'bundle' in entry else '上游远程规则集' if fields[0] == 'RULE-SET' else 'IP 地区匹配'
        title = '[' + entry['title'] + '](' + fields[1] + ')' if fields[0] == 'RULE-SET' else entry['title']
        overview += '| ' + str(i) + ' | ' + title + ' | ' + fields[2] + ' | ' + content + ' |\n'
    (ROOT / 'release/分类清单.md').write_text(overview, encoding='utf-8')
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(text, encoding='utf-8')
    print('Validated public routing module:', len(entries), 'annotated rules,', len(artifacts), 'bundles')


if __name__ == '__main__':
    main()
