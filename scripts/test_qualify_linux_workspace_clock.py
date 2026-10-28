#!/usr/bin/env python3
"""Synthetic acceptance and falsification: no network, VM or clock changes."""
import copy
import datetime
import importlib.util
import pathlib
import tempfile
import json
import unittest
from unittest import mock

spec=importlib.util.spec_from_file_location('clock',pathlib.Path(__file__).with_name('qualify-linux-workspace-clock.py'))
clock=importlib.util.module_from_spec(spec)
spec.loader.exec_module(clock)
from g3_coverage import campaign_coverage, coverage_verdict, inventory, propagate

S=clock.SECOND
START=10*S
UTC=clock.utc_ns('2026-10-27T00:00:00Z')
RUN='one-continuous-run'


def observation(slot,closing=False):
    began=START+slot*30*S
    rtc=datetime.datetime.fromtimestamp((UTC+slot*30*S)//S,datetime.timezone.utc).isoformat()
    wall=datetime.datetime.fromtimestamp((UTC+slot*30*S+205_000_000)/S,datetime.timezone.utc).isoformat()
    refs=[dict(server=host,protocol='NTS',authenticated=True,unix_ns=UTC+slot*30*S+105_000_000,
               uncertainty_ns=1000,query_began_ns=began+100_000_000,query_ended_ns=began+110_000_000)
          for host in ('time.cloudflare.com','nts.netnod.se')]
    return dict(run_id=RUN,run_start_ns=START,observation='closing' if closing else 'opening' if slot==0 else 'ordinary',
                interval_slot=None if closing else slot,reference_began_ns=began,reference_ended_ns=began+120_000_000,
                sample_began_ns=began+200_000_000,sample_ended_ns=began+210_000_000,
                host_wall_pair=dict(began_ns=began+180_000_000,ended_ns=began+180_001_000,wall_ns=UTC+slot*30*S+180_000_500),
                independent_reference=dict(references=refs,clock=clock.REFERENCE_CLOCK),
                sample=dict(measurement=dict(rtc=rtc,wall_after=wall,sample_age_ns=1000,elapsed_end_ns=slot*30*S,generation=1),
                            elapsed_ns=slot*30*S,wall_ns=UTC+slot*30*S+205_000_000,boot_id='one-product-boot',service_pid='444'))


def verdict(rows,seconds=72*3600,envelope=None,disruptions=()):
    return coverage_verdict(copy.deepcopy(rows),START,seconds,RUN,clock.reference_interval,clock.evaluate,envelope,disruptions)


class QualificationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.full=[observation(n) for n in range(8640)]+[observation(8640,True)]

    def test_exact_continuous_72_hours_and_closing(self):
        result=verdict(self.full)
        self.assertEqual(result['utc'],'pass',result['missing'][:3])
        self.assertEqual(result['unique_slots'],8640)
        self.assertEqual(result['direct_reference_slots'],8640)
        self.assertEqual(result['minimum_reference_slots'],8554)
        self.assertTrue(result['directly_referenced_endpoints'])

    def test_required_falsifications_never_pass(self):
        for name,edit in (
            ('single unbounded gap',lambda r:r[1].update(independent_reference=None)),
            ('missing closing anchor',lambda r:r.pop()),
            ('disagreeing reference',lambda r:r[4]['independent_reference']['references'][1].update(unix_ns=UTC+999*S)),
            ('spliced run',lambda r:r[10].update(run_id='second-run')),
            ('spliced start',lambda r:r[10].update(run_start_ns=START+1)),
            ('spliced guest',lambda r:r[10]['sample'].update(boot_id='different-boot')),
            ('restarted guest owner',lambda r:r[10]['sample'].update(service_pid='445')),
            ('duplicated slot',lambda r:r.insert(2,copy.deepcopy(r[1]))),
            ('missing ordinary sample',lambda r:r[3].pop('sample')),
            ('missing host bracket',lambda r:r[3].pop('host_wall_pair')),
            ('reversed host bracket',lambda r:r[3]['host_wall_pair'].update(began_ns=999999999999999)),
            ('unplanned authority pause',lambda r:r[5].update(failures=['authority paused'])),
            ('prior failure on retry',lambda r:r[6].update(bound_violation=True,error='previous violation')),
        ):
            with self.subTest(name=name):
                rows=copy.deepcopy(self.full);edit(rows)
                result=verdict(rows)
                self.assertNotEqual(result['utc'],'pass')
                if name in ('disagreeing reference','prior failure on retry','unplanned authority pause'):
                    self.assertEqual(result['utc'],'fail')

    def test_bracketed_gap_requires_independent_pinned_envelope(self):
        rows=copy.deepcopy(self.full);rows[3]['independent_reference']=None
        envelope=dict(independent=True,support_sha256='external-pointwise-rate-evidence',pinned_before_start=True,rho_ppm=500)
        result=verdict(rows,envelope=envelope)
        self.assertEqual(result['utc'],'pass',result['missing'])
        self.assertEqual(result['bounded_gap_slots'],1)
        self.assertEqual(result['direct_reference_slots'],8639)
        for edits in ({'independent':False},{'support_sha256':None},{'pinned_before_start':False},{'rho_ppm':501}):
            unsupported=dict(envelope,**edits)
            self.assertEqual(verdict(rows,envelope=unsupported)['utc'],'inconclusive')
        for n in range(1,5): rows[n]['independent_reference']=None
        self.assertEqual(verdict(rows,envelope=envelope)['utc'],'inconclusive')
        # The whole timing bracket and both directions are retained.
        self.assertEqual(propagate(dict(begin_ns=0,end_ns=2*S,utc_interval_ns=(100*S,102*S)),60*S,61*S,500),
                         (158*S-30_500_000,163*S+30_500_000))

    def test_disruption_invalidates_even_complete_evidence(self):
        for event in ('authority pause','host sleep','host reboot','guest owner restart','peer lost'):
            result=verdict(self.full,disruptions=[event])
            self.assertEqual(result['utc'],'inconclusive')
            self.assertEqual(result['invalid'],[event])

    def test_missing_opening_never_extrapolates(self):
        rows=copy.deepcopy(self.full);rows[0]['independent_reference']=None
        envelope=dict(independent=True,support_sha256='external',pinned_before_start=True,rho_ppm=500)
        self.assertEqual(verdict(rows,envelope=envelope)['utc'],'inconclusive')

    def test_aliases_count_one_and_disagreement_is_retained(self):
        row=observation(0);refs=row['independent_reference']['references']
        refs[0]['server']='sth1.nts.netnod.se'
        with self.assertRaises(ValueError): clock.reference_interval(refs,START,START+S,START,START+S)
        refs[0]['server']='time.cloudflare.com'
        disagree=copy.deepcopy(refs[0]);disagree['server']='ptbtime1.ptb.de';disagree['unix_ns']+=5*S
        with self.assertRaises(clock.ReferenceDisagreement):
            clock.reference_interval(refs+[disagree],START,START+S,START,START+S)
        refs[1]['server']='pilot.time.nl'
        with self.assertRaises(ValueError): clock.reference_interval(refs,START,START+S,START,START+S)

    def test_reference_timestamp_brackets_and_authentication(self):
        row=observation(0);refs=row['independent_reference']['references']
        interval=clock.reference_interval(refs,START,START+120_000_000,START+200_000_000,START+210_000_000,clock.REFERENCE_CLOCK)
        self.assertEqual(interval,(UTC+195_000_000-1000,UTC+215_000_000+1000))
        for field,value in (('authenticated',False),('query_began_ns',START-1),('query_ended_ns',START+121_000_000),('uncertainty_ns',True)):
            invalid=copy.deepcopy(refs);invalid[0][field]=value
            with self.assertRaises(ValueError): clock.reference_interval(invalid,START,START+120_000_000,START+200_000_000,START+210_000_000,clock.REFERENCE_CLOCK)
        with self.assertRaises(ValueError): clock.reference_interval(refs,START,START+S,START,START+S,'other.clock')

    def test_allocations_remain_binding(self):
        row=observation(0);sample=row['sample']
        for field,value in (('sample_age_ns',250_000_001),):
            invalid=copy.deepcopy(sample);invalid['measurement'][field]=value
            with self.assertRaises(clock.BoundViolation):clock.evaluate(invalid)
        sample['wall_ns']+=250_000_001
        with self.assertRaises(clock.BoundViolation):clock.evaluate(sample)
        row=observation(0)
        self.assertEqual(clock.evaluate(row['sample'],(UTC+3*S,UTC+3*S+1000))['source'],'fail')
        self.assertEqual(clock.evaluate(row['sample'])['source'],'inconclusive')

    def test_generation_projection_never_crosses_pause(self):
        rows=[observation(0),observation(1),observation(2,True)]
        rows[1]['sample']['measurement']['elapsed_end_ns']=-600*S
        self.assertEqual(verdict(rows,seconds=60)['utc'],'inconclusive')
        window=dict(verified=True,run_id=RUN,begin_ns=rows[1]['sample_began_ns'],end_ns=rows[1]['sample_ended_ns'])
        rows[1]['planned_window']=window
        result=verdict(rows,seconds=60)
        self.assertEqual(result['utc'],'pass')
        self.assertEqual(result['planned_unavailability_slots'],1)
        rows[1]['planned_window']['verified']=False
        self.assertEqual(verdict(rows,seconds=60)['utc'],'inconclusive')

    def test_exact_inventory_identity_and_load(self):
        rows=[]
        for (block,mode,duration),load in inventory().items():
            begin=START+(block*6*3600+(3*3600 if load=='load' else 0)+900)*S
            case=dict(block=block,fencing=mode,pause_seconds=duration,load=load,run_start_ns=START)
            rows.append(dict(case=case,trace=dict(load=load,pause_confirmed_host_ns=begin,boot_id='product-boot',resume_requested_host_ns=begin+int(duration*S),
                         requested_pause_seconds=duration,fencing=mode,recovery=dict(generation=block+1),
                         load_evidence=dict(load=load,run_start_ns=START,block=block*2+(load=='load'),pid=123 if load=='load' else None)),
                first_read=dict(vm='product',operation_prestarted=True,host_round_trip_after_resume=False,generation=block,generation_after=block,armed_generation=block,
                                boot_id='product-boot',sample_began_ns=begin+int(duration*S)),first_read_source='pass',
                duplicate_readers=dict(vm='product',read_only=True,second_open_busy=True,readers=8,samples=8000,maximum_ns=250_000_000)))
        result=campaign_coverage(rows,[])
        self.assertEqual(result['completed'],288)
        self.assertTrue(result['first_read_after_resume'])
        self.assertTrue(result['concurrent_duplicate_readers'])
        straddled=copy.deepcopy(rows)
        straddled[0]['first_read']['generation_after']=straddled[0]['first_read']['generation']+1
        self.assertTrue(campaign_coverage(straddled,[])['first_read_after_resume'])
        for name,edit in (
            ('duplicate identity',lambda r:r.__setitem__(1,copy.deepcopy(r[0]))),
            ('wrong load',lambda r:r[0]['trace'].update(load='load')),
            ('fixture first read',lambda r:r[0]['first_read'].update(vm='fixture')),
            ('generation change',lambda r:r[0]['first_read'].update(generation_after=999)),
            ('fixture contention',lambda r:r[0]['duplicate_readers'].update(vm='fixture')),
            ('too few readers',lambda r:r[0]['duplicate_readers'].update(readers=7)),
            ('too few reads',lambda r:r[0]['duplicate_readers'].update(samples=7999)),
            ('old read',lambda r:r[0]['duplicate_readers'].update(maximum_ns=250_000_001)),
        ):
            with self.subTest(name=name):
                invalid=copy.deepcopy(rows);edit(invalid);result=campaign_coverage(invalid,[])
                self.assertFalse(result['complete'] and result['first_read_after_resume'] and result['concurrent_duplicate_readers'])

    def test_live_loop_uses_half_open_slots_and_separate_closing(self):
        elapsed=[10.0]
        def probe(command,**kwargs):
            ns=int(elapsed[0]*S)
            if command[0]=='adapter':
                return json.dumps(dict(clock=clock.REFERENCE_CLOCK,references=[dict(server=host,protocol='NTS',authenticated=True,
                    unix_ns=UTC+int((elapsed[0]-10)*S)+S//2,uncertainty_ns=1000,query_began_ns=ns,query_ended_ns=ns)
                    for host in ('time.cloudflare.com','nts.netnod.se')]))
            value=observation(round((elapsed[0]-10)/30))['sample']
            value['wall_ns']=UTC+int((elapsed[0]-10)*S)+S//2
            value['measurement']['wall_after']=datetime.datetime.fromtimestamp(value['wall_ns']/S,datetime.timezone.utc).isoformat()
            return json.dumps(value)
        with tempfile.TemporaryDirectory() as directory:
            root=pathlib.Path(directory);image=root/'image';image.mkdir();(image/'manifest.json').write_text('{}')
            with mock.patch('sys.argv',['qualify',str(image),'unused',str(root/'evidence'),'--utc-reference-command','adapter']), \
                 mock.patch.object(clock,'host_pair',return_value=(1000,2000)), \
                 mock.patch.object(clock.time,'monotonic',side_effect=lambda:elapsed[0]), \
                 mock.patch.object(clock.time,'monotonic_ns',side_effect=lambda:int(elapsed[0]*S)), \
                 mock.patch.object(clock.time,'time_ns',side_effect=lambda:UTC+int((elapsed[0]-10)*S)+S//2), \
                 mock.patch.object(clock.time,'sleep',side_effect=lambda n:elapsed.__setitem__(0,elapsed[0]+n)), \
                 mock.patch.object(clock.subprocess,'check_output',side_effect=probe),mock.patch('builtins.print'):
                self.assertEqual(clock.main(),0)
            result=json.loads((root/'evidence/result.json').read_text())
            self.assertEqual(result['samples'],3)
            self.assertEqual(result['coverage']['unique_slots'],2)
            self.assertEqual(result['reference_coverage'],2)
            self.assertTrue(result['proof_source_coverage_qualified'],result['coverage'])
            self.assertEqual(result['utc'],'inconclusive')

    def test_only_causal_pause_timeouts_are_planned(self):
        row=observation(0)
        trace=dict(fence_requested_host_ns=row['sample_began_ns'],fresh_permission_observed_host_ns=row['sample_ended_ns'],
                   peer_receipt_observed_host_ns=row['sample_ended_ns'])
        campaign=mock.Mock(records=[dict(case=dict(run_id=RUN,block=0,fencing='normal',pause_seconds=.1),trace=trace)])
        for kind,planned in (('CalledProcessError',False),('TimeoutExpired',True)):
            invalid=copy.deepcopy(row);invalid.pop('sample');invalid['error_type']=kind
            clock.attach_planned_windows([invalid],campaign)
            self.assertEqual('planned_window' in invalid,planned)
        # No old generation may escape a completed recovery window.
        trace['product_first_read']=dict(boottime_began_ns=31*S,generation=2)
        trace['recovery']=dict(generation=2)
        later=observation(1)
        later['sample']['measurement']['generation']=1
        clock.attach_planned_windows([later],campaign)
        self.assertNotIn('sample',later)
        self.assertIn('projection crosses',later['error'])
        fresh=observation(1);fresh['sample']['measurement']['generation']=2
        clock.attach_planned_windows([fresh],campaign)
        self.assertIn('sample',fresh)  # The service may read before the diagnostic reader.

    def test_load_ends_by_own_stdin_eof(self):
        load=mock.Mock();load.wait.return_value=0
        self.assertTrue(clock.stop_load(load));load.stdin.close.assert_called_once();load.terminate.assert_not_called()

    def test_nanoseconds_are_exact(self):
        self.assertEqual(clock.utc_ns('2026-10-27T00:00:00.123456789Z')-UTC,123456789)


if __name__=='__main__':unittest.main()
