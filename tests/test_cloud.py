import hashlib
import importlib.util
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import render_module as renderer
import update_upstream as updater


class CloudTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        for folder in ('config', 'rules', 'upstream'):
            shutil.copytree(ROOT / folder, self.root / folder)

    def tearDown(self):
        self.temp.cleanup()

    def change_source(self, text):
        (self.root / 'upstream/lazy_group.conf').write_text(text)
        path = self.root / 'upstream/source.json'
        data = json.loads(path.read_text())
        data['sha256'] = hashlib.sha256(text.encode()).hexdigest()
        path.write_text(json.dumps(data))

    def test_module_keeps_local_private_settings_and_final_out(self):
        text = renderer.render(self.root)
        self.assertEqual(list(renderer.parse(text)), ['rule'])
        self.assertNotIn('FINAL,', text)
        self.assertNotIn('谷歌AI', text)
        entries, artifacts = renderer.bundle_plan(self.root)
        self.assertTrue(artifacts)
        flattened = [line for entry in entries for line in entry['expanded']]
        self.assertEqual(flattened, renderer.expanded_rules(self.root))
        self.assertIn('DOMAIN,antigravity-unleash.goog,谷歌服务', flattened)
        self.assertIn('IP-CIDR,20.46.119.115/32,DIRECT,no-resolve', flattened)
        self.assertIn(' // Google · 常规服务', text)
        for entry in entries:
            if 'bundle' in entry:
                policy = entry['rule'].split(',')[2]
                actual = [renderer.rule_with_policy(s, policy) for s in renderer.active(artifacts[entry['bundle']].splitlines())]
                self.assertEqual(actual, entry['expanded'])

    def test_supported_upstream_addition_keeps_auto_publication_working(self):
        path = self.root / 'upstream/lazy_group.conf'
        self.change_source(path.read_text().replace('\nFINAL,PROXY\n', '\nDOMAIN,new-supported.example,AI\nFINAL,PROXY\n'))
        entries, _ = renderer.bundle_plan(self.root)
        self.assertEqual([r for e in entries for r in e['expanded']], renderer.expanded_rules(self.root))
        self.assertIn('DOMAIN,new-supported.example,AI', [r for e in entries for r in e['expanded']])

    def test_local_publication_check_rejects_unpublished_or_changed_bundle(self):
        import build
        with patch.object(build.urllib.request, 'build_opener') as make:
            make.return_value.open.side_effect = OSError('not published')
            with self.assertRaisesRegex(ValueError, 'Publish and verify'):
                build.verify_publication(self.root)
        class Response:
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def read(self, size): return b'wrong content'
        with patch.object(build.urllib.request, 'build_opener') as make:
            make.return_value.open.return_value = Response()
            with self.assertRaisesRegex(ValueError, 'Publish and verify'):
                build.verify_publication(self.root)

    def test_hash_mismatch_blocks_publication(self):
        with (self.root / 'upstream/lazy_group.conf').open('a') as f:
            f.write('\n# altered\n')
        with self.assertRaisesRegex(ValueError, 'hash'):
            renderer.render(self.root)

    def test_new_policy_requires_local_support_before_publication(self):
        path = self.root / 'upstream/lazy_group.conf'
        self.change_source(path.read_text().replace('\nFINAL,PROXY\n', '\nDOMAIN,new.example,UnavailableGroup\nFINAL,PROXY\n'))
        with self.assertRaisesRegex(ValueError, 'unavailable'):
            renderer.render(self.root)

    def test_private_remote_rule_url_is_rejected(self):
        path = self.root / 'upstream/lazy_group.conf'
        self.change_source(path.read_text().replace('\nFINAL,PROXY\n', '\nRULE-SET,https://user:secret@example.com/rules,PROXY\nFINAL,PROXY\n'))
        with self.assertRaisesRegex(ValueError, 'approved public'):
            renderer.render(self.root)

    def test_archive_supports_multiple_cloud_updates(self):
        old = json.loads((self.root / 'upstream/source.json').read_text())
        initial = (self.root / 'upstream/lazy_group.conf').read_bytes()
        class Response:
            def __init__(self, data): self.data = data
            def read(self): return self.data
        for char in ('a', 'b'):
            latest = [{'sha': char * 40, 'commit': {'committer': {'date': '2026-10-20T00:00:00Z'}}}]
            raw = initial + ('\n# revision ' + char + '\n').encode()
            with patch.object(updater, 'ROOT', self.root), patch.object(sys, 'argv', ['update_upstream.py', '--archive']), patch.object(updater.urllib.request, 'build_opener') as make:
                make.return_value.open.side_effect = [Response(json.dumps(latest).encode()), Response(raw)]
                updater.main()
        self.assertEqual((self.root / 'upstream/history' / (old['commit'] + '.conf')).read_bytes(), initial)
        self.assertTrue((self.root / 'upstream/history' / ('a' * 40 + '.conf')).exists())
        self.assertFalse((self.root / 'upstream/previous.lazy_group.conf').exists())


if __name__ == '__main__':
    unittest.main()
