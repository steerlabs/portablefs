#!/usr/bin/env python3
"""Continuity and generation controls without guests or Docker."""
import json
import pathlib
import tempfile
import unittest
from unittest import mock
import g3_continuity
import g3_product_rtc_reader


class SupportTests(unittest.TestCase):
    def continuity(self,path):
        guard=g3_continuity.Continuity.__new__(g3_continuity.Continuity)
        guard.host=(1000,2000)
        guard.initial={'pid':7,'started':'same','processes':{}}
        guard.snapshot=lambda:guard.initial
        guard.guest=mock.Mock();guard.guest.p.poll.return_value=None
        guard.guest_identity='same-guest';guard.guest.ssh.return_value='same-guest'
        guard.peer_log=path;guard.last_peer=1;guard.last_peer_host=100_000_000_000
        return guard

    def test_healthy_planned_pause_does_not_need_guest_ssh(self):
        with tempfile.TemporaryDirectory() as directory:
            log=pathlib.Path(directory)/'peer.jsonl';log.write_text(json.dumps({'peer_completed_ns':2})+'\n')
            guard=self.continuity(log)
            with mock.patch.object(g3_continuity,'host_pair',return_value=(1100,1900)),mock.patch.object(g3_continuity.time,'monotonic_ns',return_value=101_000_000_000):
                guard.check(campaign_active=True)
            guard.guest.ssh.assert_not_called()
            self.assertEqual(guard.last_peer,2)

    def test_disruptions_are_detected(self):
        for name,edit in (
            ('authority restart',lambda g:setattr(g,'snapshot',lambda:{'pid':8})),
            ('guest owner exit',lambda g:setattr(g.guest.p.poll,'return_value',1)),
            ('guest restart',lambda g:setattr(g.guest.ssh,'return_value','new-guest')),
            ('peer restart',lambda g:setattr(g,'last_peer',3)),
            ('peer stalled',lambda g:setattr(g,'last_peer_host',0)),
        ):
            with self.subTest(name=name),tempfile.TemporaryDirectory() as directory:
                log=pathlib.Path(directory)/'peer.jsonl';log.write_text(json.dumps({'peer_completed_ns':2})+'\n')
                guard=self.continuity(log);guard.last_peer=2;edit(guard)
                with mock.patch.object(g3_continuity,'host_pair',return_value=(1100,1900)),mock.patch.object(g3_continuity.time,'monotonic_ns',return_value=101_000_000_000):
                    with self.assertRaises(RuntimeError):guard.check()
        with tempfile.TemporaryDirectory() as directory:
            guard=self.continuity(pathlib.Path(directory)/'unused')
            with mock.patch.object(g3_continuity,'host_pair',return_value=(2_000_000,2_001_000)):
                with self.assertRaisesRegex(RuntimeError,'host sleep'):guard.check()

    def test_host_sleep_is_checked_by_the_sampler_as_well_as_owner(self):
        self.assertEqual(g3_continuity.verify_awake((1000,2000),(1100,1900)),(1100,1900))
        with self.assertRaises(RuntimeError):g3_continuity.verify_awake((1000,2000),(2_000_000,2_001_000))

    def test_first_disruption_is_preserved_atomically(self):
        with tempfile.TemporaryDirectory() as directory:
            path=pathlib.Path(directory)/'INVALID.json'
            g3_continuity.record_invalid(path,dict(error='first pause'))
            g3_continuity.record_invalid(path,dict(error='later timeout'))
            self.assertEqual(json.loads(path.read_text())['error'],'first pause')

    def test_sampler_refuses_lost_or_stale_owner(self):
        with tempfile.TemporaryDirectory() as directory:
            path=pathlib.Path(directory)/'status.json'
            value=dict(pid=42,run_id='one-run',continuity=dict(observed_ns=100_000_000_000))
            path.write_text(json.dumps(value))
            self.assertEqual(g3_continuity.verify_owner(path,42,'one-run',101_000_000_000,42),100_000_000_000)
            for args in ((42,'one-run',101_000_000_000,1),(43,'one-run',101_000_000_000,43),
                         (42,'other-run',101_000_000_000,42),(42,'one-run',146_000_000_000,42)):
                with self.assertRaises(RuntimeError):g3_continuity.verify_owner(path,*args)

    def test_hold_defers_container_cleanup_and_stops_only_owned_guest(self):
        import importlib.util
        spec=importlib.util.spec_from_file_location('owner',pathlib.Path(__file__).with_name('qualify-linux-workspace-run.py'))
        owner=importlib.util.module_from_spec(spec);spec.loader.exec_module(owner)
        with tempfile.TemporaryDirectory() as directory:
            hold=pathlib.Path(directory)/'HOLD';hold.touch()
            authority=mock.Mock(name='owned-authority');authority.name='pfs-g3-owned'
            guest=mock.Mock();peer=mock.Mock();peer.poll.return_value=None
            status=dict(errors=[])
            owner.cleanup_owned_resources(authority,guest,{'owned':'mount'},peer,hold,status)
            authority.unmount.assert_not_called();authority.close.assert_not_called();peer.terminate.assert_not_called();peer.kill.assert_not_called()
            guest.stop.assert_called_once()
            self.assertEqual(status['deferred_container_cleanup']['container'],'pfs-g3-owned')
            hold.unlink();guest.reset_mock()
            owner.cleanup_owned_resources(authority,guest,{'owned':'mount'},peer,hold,status)
            authority.unmount.assert_called_once_with(guest,{'owned':'mount'});authority.close.assert_called_once();guest.stop.assert_called_once()

    def test_probe_transport_owns_its_socket_and_exact_process(self):
        import importlib.util
        spec=importlib.util.spec_from_file_location('probe_clock',pathlib.Path(__file__).with_name('qualify-linux-workspace-clock.py'))
        clock=importlib.util.module_from_spec(spec);spec.loader.exec_module(clock)
        with tempfile.TemporaryDirectory() as directory:
            root=pathlib.Path(directory);control=root/'probe.sock'
            process=mock.Mock();process.poll.return_value=None
            def start(*args,**kwargs):control.touch();return process
            with mock.patch.object(clock.subprocess,'Popen',side_effect=start) as popen,mock.patch.object(clock.subprocess,'check_output',return_value='') as check:
                transport=clock.ProbeTransport(['ssh','-F','owned-config','guest'],control,root)
                self.assertIn('ServerAliveInterval=0',transport.command)
                self.assertIn('TCPKeepAlive=no',transport.command)
                self.assertNotIn('-O',popen.call_args.args[0])
                self.assertEqual(popen.call_args.args[0][popen.call_args.args[0].index('-S')+1],str(control))
                check.assert_called_once_with(transport.command+['true'],text=True,timeout=10)
                transport.close();process.terminate.assert_called_once();process.wait.assert_called_once_with(timeout=5)
                with self.assertRaisesRegex(RuntimeError,'existing probe control socket'):
                    clock.ProbeTransport(['ssh','guest'],control,root)
            control.unlink();process.reset_mock();process.poll.return_value=1
            with mock.patch.object(clock.subprocess,'Popen',return_value=process):
                with self.assertRaisesRegex(RuntimeError,'before readiness'):
                    clock.ProbeTransport(['ssh','guest'],control,root)
            process.terminate.assert_not_called()

    def test_product_generation_requires_even_stable_seqlock(self):
        import struct
        page=bytearray(4096);struct.pack_into('<QQ',page,128,2,42)
        self.assertEqual(g3_product_rtc_reader.generation(page),42)
        struct.pack_into('<Q',page,128,3)
        with self.assertRaises(RuntimeError):g3_product_rtc_reader.generation(page)

    def test_guest_stop_requires_a_terminal_operation_and_zero_owner_exit(self):
        import importlib.util
        spec=importlib.util.spec_from_file_location('stop_owner',pathlib.Path(__file__).with_name('qualify-linux-workspace-run.py'))
        owner=importlib.util.module_from_spec(spec);spec.loader.exec_module(owner)
        for operation in ('shutdown-completed','stop-completed','shutdown-request'):
            for code in (0,1):
                with self.subTest(operation=operation,code=code):
                    guest=owner.Guest.__new__(owner.Guest)
                    guest.p=mock.Mock();guest.p.poll.return_value=None;guest.p.wait.return_value=code
                    guest.command=mock.Mock();guest.wait=mock.Mock(return_value=dict(operations=[operation]))
                    if operation=='shutdown-request' or code:
                        with self.assertRaises(AssertionError):guest.stop()
                    else:
                        self.assertEqual(guest.stop(),dict(outcome=operation,graceful=operation=='shutdown-completed',owner_returncode=0))
                        guest.p.wait.assert_called_once_with(timeout=10)

    def test_global_hold_stops_proof_but_exempts_running_soak(self):
        import importlib.util
        spec=importlib.util.spec_from_file_location('hold_owner',pathlib.Path(__file__).with_name('qualify-linux-workspace-run.py'))
        owner=importlib.util.module_from_spec(spec);spec.loader.exec_module(owner)
        with tempfile.TemporaryDirectory() as directory:
            hold=pathlib.Path(directory)/'HOLD'
            self.assertFalse(owner.running_hold(hold,False))
            hold.touch()
            self.assertTrue(owner.running_hold(hold,False))
            self.assertFalse(owner.running_hold(hold,True))
            status=dict(soak=True,candidate_commit='pinned',image_manifest_sha256='digest')
            owner.write_status(pathlib.Path(directory),status,'running')
            self.assertIn('exempt from the heavy token', (pathlib.Path(directory)/'STATUS.md').read_text())


if __name__=='__main__':unittest.main()
