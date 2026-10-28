"""Immutable input identities required before starting a G3 clock run."""
import hashlib
import json
import pathlib

HARNESS = ('qualify-linux-workspace-clock.py','qualify-linux-workspace-run.py','g3_coverage.py',
           'g3_continuity.py','g3_local_authority.py','g3_product_probe.py','g3_product_rtc_reader.py','g3_pins.py',
           'linux_workspace_native_g0.py','linux_workspace_native_managed.py',
           'linux-workspace-native-authority.sh','test-linux-workspace-g0.sh',
           'test-linux-workspace-g0.swift','test-linux-workspace-rtc.sh','test-linux-workspace-rtc.swift',
           'nts-reference/policy.json')


def digest(path):
    value=hashlib.sha256()
    with pathlib.Path(path).open('rb') as stream:
        while block:=stream.read(1024*1024): value.update(block)
    return value.hexdigest()


def verify(pins, root, image, owner, reference):
    required={name:digest(root/name) for name in HARNESS}
    if pins.get('harness_sha256') != required:
        raise ValueError('harness/reference policy differs from pinned inputs')
    if pins.get('owner_sha256') != digest(owner) or pins.get('reference_sha256') != digest(reference):
        raise ValueError('owner or NTS binary differs from pinned inputs')
    if pins.get('image_manifest_sha256') != digest(image/'manifest.json'):
        raise ValueError('image manifest differs from pinned inputs')
    release=json.loads((image/'manifest.json').read_text())['release']
    if pins.get('image_commit') != release['commit'] or not pins.get('candidate_commit'):
        raise ValueError('missing candidate/image source identity')
    if pins.get('reference_policy') != 'astra-g3-2026-10-27' or pins.get('rate_envelope') is not None:
        raise ValueError('this run uses direct collection; no independent holdover envelope is supplied')
    return pins
