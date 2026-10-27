#!/usr/bin/env python3
"""Falsify UTC/reference arithmetic without clocks, networking or a guest."""
import importlib.util
import pathlib
import unittest
import json
import tempfile
import threading
import datetime
from unittest import mock

spec = importlib.util.spec_from_file_location('clock', pathlib.Path(__file__).with_name('qualify-linux-workspace-clock.py'))
clock = importlib.util.module_from_spec(spec)
spec.loader.exec_module(clock)


class QualificationTests(unittest.TestCase):
    def test_query_timing_keeps_complete_ntp_transit(self):
        refs=[dict(server=n,protocol='NTS',authenticated=True,unix_ns=1000,uncertainty_ns=5,
                   query_began_ns=102,query_ended_ns=118) for n in ('a','b')]
        self.assertEqual(clock.reference_interval(refs,100,120,130,150,clock.REFERENCE_CLOCK),(1007,1053))
        # A mismatched domain or fabricated interval cannot tighten evidence.
        # The legacy full-invocation contract remains conservative.
        self.assertEqual(clock.reference_interval(refs,100,120,130,150),(1005,1055))
        for domain in ('other',True):
            with self.assertRaises(ValueError): clock.reference_interval(refs,100,120,130,150,domain)
        for begin,end in ((99,118),(119,118),(102,121),(True,118)):
            refs[0].update(query_began_ns=begin,query_ended_ns=end)
            with self.assertRaises(ValueError): clock.reference_interval(refs,100,120,130,150,clock.REFERENCE_CLOCK)

    def test_charges_complete_reference_and_sampling_transit(self):
        refs = [dict(server=n, protocol='NTS', authenticated=True, unix_ns=1000, uncertainty_ns=5) for n in ('a','b')]
        self.assertEqual(clock.reference_interval(refs, 100, 120, 130, 150), (1005,1055))
        self.assertEqual(clock.reference_interval(refs, 100, 120, 105, 110), (980,1015))
        with self.assertRaises(ValueError):
            clock.reference_interval(refs,120,100,130,150)
        refs[1]['authenticated'] = False
        with self.assertRaises(ValueError):
            clock.reference_interval(refs,100,120,130,150)

    def test_missing_or_same_reference_is_not_coverage(self):
        ref = dict(server='a', protocol='NTS', authenticated=True, unix_ns=1000, uncertainty_ns=5)
        for refs in ([],[ref],[ref,ref]):
            with self.assertRaises(ValueError):
                clock.reference_interval(refs,100,120,130,150)

    def test_pause_campaign_binds_image_and_independent_first_read(self):
        class NoWait:
            def wait(self, seconds): return False
            def is_set(self): return False
        with tempfile.TemporaryDirectory(prefix='pfs-g0-campaign-test-') as directory:
            campaign=clock.PauseCampaign.__new__(clock.PauseCampaign)
            campaign.command='test-driver'; campaign.image_hash='candidate'
            campaign.evidence=pathlib.Path(directory); campaign.duration=1800
            campaign.dry_run=True; campaign.started=0; campaign.stop=NoWait()
            campaign.active=threading.Event(); campaign.records=[];campaign.errors=[]
            utc=clock.utc_ns('2026-10-26T00:00:00Z')
            def result(args, **kwargs):
                case=json.loads(args[-1])
                return json.dumps(dict(case=case,image_manifest_sha256='candidate',
                    first_operation_prestarted=True,denied_before_host_round_trip=True,closed_cold_fresh=True,
                    first_read=dict(rtc='2026-10-26T00:00:00Z',sample_age_ns=1000,
                        reference_began_ns=100,reference_ended_ns=120,sample_began_ns=130,sample_ended_ns=140,
                        references=[dict(server=n,protocol='NTS',authenticated=True,unix_ns=utc+500_000_000,uncertainty_ns=1000) for n in ('a','b')]),
                    duplicate_readers=dict(readers=8,samples=8000,maximum_ns=1000)))
            with mock.patch.object(clock.subprocess,'check_output',side_effect=result): campaign.run()
            self.assertEqual(len(campaign.records),3)
            self.assertFalse(campaign.errors)
            self.assertTrue(all(v['first_read_source']=='pass' for v in campaign.records))
            def failed_bound(args, **kwargs):
                value=json.loads(result(args,**kwargs))
                value['first_read']['rtc']='2026-10-26T00:00:05Z'
                return json.dumps(value)
            campaign.records=[];campaign.errors=[]
            with mock.patch.object(clock.subprocess,'check_output',side_effect=failed_bound): campaign.run()
            self.assertFalse(campaign.records)
            self.assertEqual(len(campaign.errors),3)
            self.assertTrue(all(v['bound_violation'] for v in campaign.errors))
            campaign.records=[];campaign.errors=[]
            campaign.dry_run=False;campaign.duration=6*3600
            with mock.patch.object(clock.subprocess,'check_output',side_effect=result): campaign.run()
            self.assertEqual(len(campaign.records),24)
            self.assertEqual([v['case']['load'] for v in campaign.records],['idle']*12+['load']*12)
            self.assertFalse(campaign.errors)

    def test_fractional_nanoseconds_are_not_rounded(self):
        self.assertEqual(clock.utc_ns('2026-10-26T00:00:00.123456789Z')-
                         clock.utc_ns('2026-10-26T00:00:00Z'),123456789)

    def test_pause_overlap_includes_completed_case_and_error(self):
        campaign=clock.PauseCampaign.__new__(clock.PauseCampaign)
        campaign.active=threading.Event(); campaign.records=[];campaign.errors=[]
        token=campaign.sample_token()
        self.assertFalse(campaign.overlaps_sample(token))
        campaign.active.set()
        self.assertTrue(campaign.overlaps_sample(token))

        active=campaign.sample_token()
        campaign.active.clear()
        self.assertTrue(campaign.overlaps_sample(active))
        campaign.records.append({})
        self.assertTrue(campaign.overlaps_sample(token))
        token=campaign.sample_token()
        campaign.errors.append({})
        self.assertTrue(campaign.overlaps_sample(token))

    def test_catchup_burst_cannot_fill_missing_measurement_slot(self):
        rows=[dict(interval_slot=v) for v in (0,2,2)]
        self.assertFalse(clock.measurement_coverage(rows,60))
        rows.append(dict(interval_slot=1))
        self.assertTrue(clock.measurement_coverage(rows,60))

    def test_completed_pause_does_not_validate_old_projection(self):
        campaign=clock.PauseCampaign.__new__(clock.PauseCampaign)
        campaign.active=threading.Event(); campaign.records=[];campaign.errors=[]
        campaign.finish=lambda: None
        elapsed=[0.]; calls=[0]
        epoch=datetime.datetime(2026,10,26,tzinfo=datetime.timezone.utc)
        def probe(*args, **kwargs):
            calls[0]+=1
            current=epoch+datetime.timedelta(seconds=elapsed[0])
            stamp=current.isoformat()
            sample=dict(measurement=dict(rtc=stamp,wall_after=stamp,sample_age_ns=0,
                        elapsed_end_ns=int(elapsed[0]*clock.SECOND)),
                        elapsed_ns=int(elapsed[0]*clock.SECOND),wall_ns=clock.utc_ns(stamp))
            if calls[0]==2:
                campaign.records.append({})
                sample['measurement']['elapsed_end_ns']=-600*clock.SECOND
            return json.dumps(sample)
        def advance(seconds): elapsed[0]+=seconds
        with tempfile.TemporaryDirectory(prefix='pfs-g0-overlap-test-') as directory:
            root=pathlib.Path(directory);image=root/'image';image.mkdir()
            (image/'manifest.json').write_text('{}')
            with mock.patch('sys.argv',['qualify',str(image),'unused-ssh',str(root/'evidence'),'--seconds','60']), \
                 mock.patch.object(clock,'PauseCampaign',return_value=campaign), \
                 mock.patch.object(clock.time,'monotonic',side_effect=lambda:elapsed[0]), \
                 mock.patch.object(clock.time,'monotonic_ns',side_effect=lambda:int(elapsed[0]*clock.SECOND)), \
                 mock.patch.object(clock.time,'sleep',side_effect=advance), \
                 mock.patch.object(clock.subprocess,'check_output',side_effect=probe), \
                 mock.patch('builtins.print'):
                self.assertEqual(clock.main(),0)
            result=json.loads((root/'evidence/result.json').read_text())
            rows=json.loads((root/'evidence/samples.json').read_text())
            self.assertFalse(result['failures'])
            self.assertTrue(result['measurement_coverage_complete'])
            self.assertTrue(rows[1]['intentional_pause_unavailability'])
            self.assertNotIn('checks',rows[1])

    def test_load_ends_by_own_stdin_eof(self):
        load=mock.Mock();load.wait.return_value=0
        self.assertTrue(clock.stop_load(load))
        load.stdin.close.assert_called_once()
        load.terminate.assert_not_called()
        load.wait.side_effect=[clock.subprocess.TimeoutExpired('owned-ssh',20),0]
        self.assertFalse(clock.stop_load(load))
        load.terminate.assert_called_once()

    def test_integer_nanoseconds_and_separate_source_bound(self):
        rtc = clock.utc_ns('2026-10-26T00:00:00Z')
        sample = dict(measurement=dict(rtc='2026-10-26T00:00:00Z', wall_after='2026-10-26T00:00:00.500000Z',
                                      sample_age_ns=1000, elapsed_end_ns=0), elapsed_ns=0, wall_ns=rtc+500_000_000)
        no_reference = clock.evaluate(sample)
        self.assertEqual(no_reference['source'],'inconclusive')
        self.assertEqual(clock.evaluate(sample,(rtc+499_999_000,rtc+500_001_000))['source'],'pass')
        self.assertEqual(clock.evaluate(sample,(rtc+3_000_000_000,rtc+3_000_001_000))['source'],'fail')
        sample['elapsed_ns'] = 60*clock.SECOND
        with self.assertRaises(ValueError):
            clock.evaluate(sample)

    def test_age_and_drift_allocations_fail_closed(self):
        rtc = clock.utc_ns('2026-10-26T00:00:00Z')
        sample = dict(measurement=dict(rtc='2026-10-26T00:00:00Z',wall_after='2026-10-26T00:00:00Z',
                                      sample_age_ns=250_000_001,elapsed_end_ns=0),elapsed_ns=0,wall_ns=rtc)
        with self.assertRaises(ValueError): clock.evaluate(sample)
        sample['measurement']['sample_age_ns']=0
        sample['wall_ns']+=250_000_001
        with self.assertRaises(ValueError): clock.evaluate(sample)


if __name__ == '__main__':
    unittest.main()
