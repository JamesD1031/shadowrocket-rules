#!/usr/bin/env python3
"""Check or fetch the latest public upstream file without touching the active app."""
import argparse
import datetime
import hashlib
import json
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true', help='Report latest version; do not modify any files')
    parser.add_argument('--archive', action='store_true', help='Archive old baselines by commit for unattended cloud updates')
    parser.add_argument('--proxy', help='Optional local HTTP proxy, e.g. http://127.0.0.1:1082')
    args = parser.parse_args()
    if args.proxy:
        parsed = urllib.parse.urlsplit(args.proxy)
        if parsed.hostname not in {'127.0.0.1', 'localhost', '::1'} or parsed.username or parsed.password:
            parser.error('Only a local, credential-free proxy URL is accepted')
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({'http': args.proxy, 'https': args.proxy}) if args.proxy else urllib.request.ProxyHandler())
    def fetch(url):
        return opener.open(urllib.request.Request(url, headers={'User-Agent': 'shadowrocket-configs-maintenance'}), timeout=25).read()
    path = ROOT / 'upstream/source.json'
    old = json.loads(path.read_text())
    api = 'https://api.github.com/repos/LOWERTOP/Shadowrocket/commits?path=lazy_group.conf&sha=main&per_page=1'
    latest = json.loads(fetch(api))[0]
    sha = latest['sha']
    print('Current:', old['commit'], 'Latest:', sha, 'Date:', latest['commit']['committer']['date'])
    if args.check or sha == old['commit']:
        return
    url = f'https://raw.githubusercontent.com/LOWERTOP/Shadowrocket/{sha}/lazy_group.conf'
    raw = fetch(url)
    text = raw.decode('utf-8')
    if '[Proxy Group]' not in text or '[Rule]' not in text:
        raise ValueError('Downloaded file is not a complete group configuration')
    target = ROOT / 'upstream/lazy_group.conf'
    previous = ROOT / 'upstream/previous.lazy_group.conf'
    if previous.exists() and not args.archive:
        raise ValueError('An unapplied previous upstream snapshot already exists; finish/review that migration first')
    if args.archive:
        if previous.exists():
            raise ValueError('Finish the pending manual migration before enabling unattended updates')
        archive = ROOT / 'upstream/history' / (old['commit'] + '.conf')
        archive.parent.mkdir(parents=True, exist_ok=True)
        if archive.exists() and archive.read_bytes() != target.read_bytes():
            raise ValueError('Archived baseline differs from the current source')
        archive.write_bytes(target.read_bytes())
    else:
        previous.write_bytes(target.read_bytes())
    target.write_bytes(raw)
    new = {**old, 'commit': sha, 'previous_commit': old['commit'], 'source_url': url,
           'sha256': hashlib.sha256(raw).hexdigest(), 'fetched_on': datetime.date.today().isoformat(),
           'source_commit_date': latest['commit']['committer']['date']}
    new.pop('source_file_date', None)
    path.write_text(json.dumps(new, ensure_ascii=False, indent=2) + '\n')
    print('Updated public source only; previous baseline retained in ' + ('upstream/history/' if args.archive else str(previous.relative_to(ROOT))))


if __name__ == '__main__':
    main()
