import json
import tempfile
import unittest
import zipfile
from pathlib import Path
from support_bundle import build_support_bundle

class SupportBundleTests(unittest.TestCase):
    def test_bundle_contains_summary_but_not_packet_payload(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'support.zip'
            build_support_bundle(path, diagnostics={'app_version':'test'},
                analyzer_snapshot={'packets':[{'secret_payload':'must not be included'}], 'devices':[{}], 'services':[{}], 'groups':{'_airplay._tcp':1}, 'record_types':{'PTR':1}, 'diagnostics':{'frames_seen':10}},
                discovery_events=[{'event':'error','error':'sample issue'}], app_version='test')
            with zipfile.ZipFile(path) as z:
                names = set(z.namelist())
                self.assertEqual(names, {'README.txt','runtime-diagnostics.json','capture-summary.json','bonjour-events.json'})
                summary = json.loads(z.read('capture-summary.json'))
                self.assertEqual(summary['stored_packet_count'], 1)
                self.assertEqual(summary['device_count'], 1)
                self.assertNotIn('secret_payload', z.read('capture-summary.json').decode())
                self.assertIn('Raw packet', z.read('README.txt').decode())

if __name__ == '__main__': unittest.main()
