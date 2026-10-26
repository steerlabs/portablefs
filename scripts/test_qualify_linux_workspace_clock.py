#!/usr/bin/env python3
"""Falsify UTC/reference arithmetic without clocks, networking or a guest."""
import importlib.util
import pathlib
import unittest

spec = importlib.util.spec_from_file_location('clock', pathlib.Path(__file__).with_name('qualify-linux-workspace-clock.py'))
clock = importlib.util.module_from_spec(spec)
spec.loader.exec_module(clock)


class QualificationTests(unittest.TestCase):
    def test_charges_complete_reference_and_sampling_transit(self):
        refs = [dict(server=n, protocol='NTS', authenticated=True, unix_ns=1000, uncertainty_ns=5) for n in ('a','b')]
        self.assertEqual(clock.reference_interval(refs, 100, 120, 130, 150), (1005,1055))
        refs[1]['authenticated'] = False
        with self.assertRaises(ValueError):
            clock.reference_interval(refs,100,120,130,150)

    def test_missing_or_same_reference_is_not_coverage(self):
        ref = dict(server='a', protocol='NTS', authenticated=True, unix_ns=1000, uncertainty_ns=5)
        for refs in ([],[ref],[ref,ref]):
            with self.assertRaises(ValueError):
                clock.reference_interval(refs,100,120,130,150)

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
