import unittest
from capture_compare import compare_captures


def packet(ts, src, mac, direction, records=(), questions=()):
    return {'timestamp':ts,'time':str(ts),'source':src,'destination':'224.0.0.251','mac':mac,'direction':direction,'records':list(records),'questions':list(questions)}

class CaptureCompareTests(unittest.TestCase):
    def test_added_and_removed_records_have_packet_evidence(self):
        old=[packet(1,'10.0.0.2','aa:bb','Response',[{'name':'_airplay._tcp.local','type':'PTR','value':'Living Room._airplay._tcp.local'}])]
        new=[packet(2,'10.0.0.3','cc:dd','Response',[{'name':'_googlecast._tcp.local','type':'PTR','value':'TV._googlecast._tcp.local'}])]
        result=compare_captures(old,new,'before.pcap','after.pcap')
        self.assertTrue(any('Removed from current'==x['change'] and 'packet #1' in x['evidence'] for x in result['differences']))
        self.assertTrue(any('New in current'==x['change'] and 'packet #1' in x['evidence'] for x in result['differences']))
    def test_device_appearance_and_absence_are_worded_as_observations(self):
        result=compare_captures([packet(1,'10.0.0.2','aa','Query')],[packet(2,'10.0.0.3','bb','Query')])
        changes={(x['subject'].split(' ')[0],x['change']) for x in result['differences'] if x['category']=='Device'}
        self.assertIn(('10.0.0.2','Not observed in current'),changes)
        self.assertIn(('10.0.0.3','New responding source'),changes)
    def test_traffic_counts_and_notes(self):
        result=compare_captures([packet(1,'1.1.1.1','aa','Query')],[packet(2,'1.1.1.1','aa','Query'),packet(3,'1.1.1.1','aa','Response')])
        self.assertTrue(any(x['category']=='Traffic' and x['subject']=='Packet count' for x in result['differences']))
        self.assertTrue(any('does not prove unavailable' in x for x in result['notes']))
    def test_identical_captures_no_differences(self):
        p=[packet(1,'10.0.0.2','aa','Query',[{'name':'host.local','type':'A','value':'10.0.0.2'}])]
        self.assertEqual(compare_captures(p,p)['differences'],[])

if __name__=='__main__': unittest.main()
