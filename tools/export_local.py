#!/usr/bin/env python3
"""Read-only export of the macOS Shadowrocket SQLite format used on this machine."""
import argparse
import sqlite3
from pathlib import Path
from build import BEGIN, END, write_private

DB = Path.home() / 'Library/Containers/com.liguangming.Shadowrocket/Data/Documents/Databases/managed.db'
TITLES = {'general': 'General', 'proxy': 'Proxy', 'proxygroup': 'Proxy Group', 'rule': 'Rule', 'host': 'Host', 'urlrewrite': 'URL Rewrite', 'mitm': 'MITM'}


def export(db):
    conn = sqlite3.connect('file:' + str(db.resolve()) + '?mode=ro', uri=True)
    try:
        if conn.execute('pragma quick_check').fetchone()[0] != 'ok':
            raise ValueError('Database integrity check failed')
        sections = {}
        for section, name, value, option, ext in conn.execute('select section,name,value,option,ext from config order by rowid'):
            if section not in TITLES:
                raise ValueError('Unknown database section; export using the native app instead')
            lines = sections.setdefault(section, [])
            if name == 'COMMENT':
                if section == 'rule' and value.strip() in {BEGIN, END}:
                    lines.append(value.strip())
                continue
            if section == 'rule':
                line = ','.join([name] + ([value] if value else []) + ([option] if option else []) + ([ext] if ext else []))
            elif section == 'urlrewrite':
                line = ' '.join(s for s in [name, value, option, ext] if s)
            else:
                if option or ext:
                    raise ValueError('Unexpected non-rule fields; export using the native app instead')
                line = name + ' = ' + value
            lines.append(line)
        return '\n\n'.join('[' + TITLES[k] + ']\n' + '\n'.join(v) for k, v in sections.items()) + '\n'
    finally:
        conn.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--database', type=Path, default=DB)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    write_private(args.output, export(args.database))
    print('Exported privately; database was opened read-only. Never commit this file.')
