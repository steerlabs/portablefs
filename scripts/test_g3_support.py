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

    def test_product_generation_requires_even_stable_seqlock(self):
        import struct
        page=bytearray(4096);struct.pack_into('<QQ',page,128,2,42)
        self.assertEqual(g3_product_rtc_reader.generation(page),42)
        struct.pack_into('<Q',page,128,3)
        with self.assertRaises(RuntimeError):g3_product_rtc_reader.generation(page)


if __name__=='__main__':unittest.main()
