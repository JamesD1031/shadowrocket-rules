import importlib.util
import tempfile
import unittest
import sqlite3
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('builder', ROOT / 'tools/build.py')
b = importlib.util.module_from_spec(spec)
spec.loader.exec_module(b)

UP = '''[General]
dns-server = new-default
stun-response-ip = 1.1.1.1
[Proxy Group]
AI = select,PROXY
谷歌服务 = select,PROXY
Facebook = select,PROXY
[Rule]
DOMAIN-SUFFIX,facebook.com,Facebook
FINAL,PROXY
[Host]
localhost = 127.0.0.1
'''
LOCAL = '''[General]
dns-server = personal-dns
[Proxy]
PrivateNode = socks5,127.0.0.1,10000,password=LOCAL_ONLY_SECRET
[Proxy Group]
AI = select,PROXY,PrivateNode,policy-select-name=PrivateNode
谷歌AI = select,PrivateNode
谷歌服务 = select,PROXY
Facebook(Meta) = select,PROXY
[Rule]
FINAL,PROXY
[MITM]
ca-passphrase = PRIVATE_CA_SECRET
enable = false
'''


class BuildTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        (self.root / 'rules').mkdir()
        (self.root / 'rules/test.list').write_text('DOMAIN-SUFFIX,googleapis.com\nIP-CIDR,20.46.119.115/32,no-resolve\n')
        self.manifest = {'policy_aliases': {'谷歌AI': '谷歌服务', 'Facebook': 'Facebook(Meta)'},
                         'preferred_nodes': {'谷歌服务': 'PinnedNode'},
                         'rules': [{'file': 'rules/test.list', 'policy': '谷歌服务'}]}

    def tearDown(self):
        self.temp.cleanup()

    def test_preserves_private_data_locally_and_removes_obsolete_group(self):
        text = b.build(UP, LOCAL, self.manifest, self.root, initial=True)
        self.assertIn('LOCAL_ONLY_SECRET', text)
        self.assertIn('PRIVATE_CA_SECRET', text)
        self.assertNotIn('谷歌AI =', text)
        self.assertIn('policy-select-name=PrivateNode', text)
        self.assertIn('policy-select-name=PinnedNode', text)
        self.assertIn('DOMAIN-SUFFIX,facebook.com,Facebook(Meta)', text)
        self.assertIn('IP-CIDR,20.46.119.115/32,谷歌服务,no-resolve', text)
        self.assertLess(text.index('DOMAIN-SUFFIX,googleapis.com'), text.index('FINAL,PROXY'))

    def test_new_defaults_and_personal_overrides(self):
        text = b.build(UP, LOCAL, self.manifest, self.root, initial=True)
        self.assertIn('dns-server = personal-dns', text)
        self.assertIn('stun-response-ip = 1.1.1.1', text)
        old = UP.replace('new-default', 'old-default')
        local = LOCAL.replace('personal-dns', 'old-default')
        text = b.build(UP, local, self.manifest, self.root, previous_text=old, initial=True)
        self.assertIn('dns-server = new-default', text)

    def test_unmanaged_rules_are_not_silently_discarded(self):
        first = b.build(UP, LOCAL, self.manifest, self.root, initial=True)
        second = b.build(UP, first, self.manifest, self.root)
        self.assertIn('LOCAL_ONLY_SECRET', second)
        with self.assertRaisesRegex(ValueError, 'Unmanaged'):
            b.build(UP, first.replace('FINAL,PROXY', 'DOMAIN,new-private.example,PROXY\nFINAL,PROXY'), self.manifest, self.root)

    def test_private_output_cannot_be_written_inside_repository(self):
        with self.assertRaises(ValueError):
            b.private_output(ROOT / 'generated.conf')

    def test_deleted_upstream_rewrites_follow_update(self):
        previous = UP + '[URL Rewrite]\n^https://old.example https://new.example 302\n'
        local = LOCAL + '[URL Rewrite]\n^https://old.example https://new.example 302\n^https://personal.example https://mine.example 302\n'
        text = b.build(UP, local, self.manifest, self.root, previous_text=previous, initial=True)
        self.assertNotIn('https://old.example', text)
        self.assertIn('https://personal.example', text)

    def test_rule_list_cannot_smuggle_policy_or_remote_url(self):
        with self.assertRaises(ValueError):
            b.rule_with_policy('DOMAIN,example.com,OTHER_POLICY', '谷歌服务')

    def test_sqlite_export_preserves_rebuild_markers(self):
        database = self.root / 'local.db'
        conn = sqlite3.connect(database)
        conn.execute('create table config (section,name,value,option,ext,remarks)')
        conn.executemany('insert into config values (?,?,?,?,?,?)', [
            ('rule', 'COMMENT', b.BEGIN, '0', '0', ''),
            ('rule', 'DOMAIN', 'example.com', 'PROXY', '', '示例规则'),
            ('rule', 'COMMENT', b.END, '0', '0', ''),
            ('rule', 'FINAL', '', 'PROXY', '', '')])
        conn.commit(); conn.close()
        output = self.root / 'private.conf'
        subprocess.run([sys.executable, str(ROOT / 'tools/export_local.py'), '--database', str(database), '--output', str(output)], check=True, capture_output=True)
        text = output.read_text()
        self.assertIn(b.BEGIN, text)
        self.assertIn(b.END, text)
        self.assertIn('DOMAIN,example.com,PROXY // 示例规则', text)
        self.assertLess(text.index(b.BEGIN), text.index('DOMAIN,example.com,PROXY'))
        self.assertEqual(output.stat().st_mode & 0o777, 0o600)


if __name__ == '__main__':
    unittest.main()
