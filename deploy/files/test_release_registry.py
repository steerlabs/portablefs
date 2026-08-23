#!/usr/bin/env python3
"""Adversarial pure tests for the immutable PortableFS registry boundary."""

from __future__ import annotations

import copy
import gzip
import hashlib
import importlib.util
import io
import json
import sys
import tarfile
import tempfile
import unittest
from dataclasses import dataclass
from pathlib import Path
from unittest.mock import patch


MODULE_PATH = Path(__file__).with_name("release_registry.py")
SPEC = importlib.util.spec_from_file_location("portablefs_release_registry", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
release = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = release
SPEC.loader.exec_module(release)

SOURCE = "a" * 40
RELEASE_ID = f"pfs-hosted-20260823-{SOURCE[:12]}"
FILES_IMAGE = f"{release.FILES_REPOSITORY}@sha256:{'b' * 64}"


@dataclass
class EntrySpec:
    kind: str
    mode: int
    uid: int = 0
    gid: int = 0
    data: bytes = b""
    linkname: str = ""


@dataclass
class Fixture:
    root: Path
    root_manifest: Path
    manifest: Path
    blobs: Path
    digest: str
    entries: dict[str, EntrySpec]
    config: dict


def helper_bytes() -> dict[str, bytes]:
    return {
        destination: (release.ROOT / source).read_bytes()
        for source, destination in release.HELPERS.items()
    }


def hosted_bytes() -> dict[str, bytes]:
    values: dict[str, bytes] = {}
    for relative in release.HOSTED_MODES:
        if relative == "SHA256SUMS":
            continue
        if relative == "architecture":
            values[relative] = b"amd64\n"
        elif relative == "source-commit":
            values[relative] = f"{SOURCE}\n".encode()
        elif relative == "release-id":
            values[relative] = f"{RELEASE_ID}\n".encode()
        elif relative.startswith("bin/") or relative.startswith("libexec/"):
            values[relative] = b"\x7fELF" + relative.encode()
        else:
            values[relative] = f"unit:{relative}\n".encode()
    checksum = "".join(
        f"{hashlib.sha256(values[name]).hexdigest()}  {name}\n"
        for name in sorted(values)
    ).encode()
    values["SHA256SUMS"] = checksum
    return values


def capsule_entries() -> dict[str, EntrySpec]:
    entries = {
        path: EntrySpec("directory", 0o755) for path in release.CAPSULE_DIRECTORIES
    }
    hosted = hosted_bytes()
    client = f"{release.CAPSULE_PREFIX}/hosted/bin/portablefs"
    record = release.expected_release_record(
        SOURCE,
        RELEASE_ID,
        FILES_IMAGE,
        release.sha256_bytes(hosted["bin/portablefs"]),
    )
    entries[release.CAPSULE_RECORD_PATH] = EntrySpec(
        "file", 0o444, data=release.canonical_json(record)
    )
    for relative, mode in release.HOSTED_MODES.items():
        entries[f"{release.CAPSULE_PREFIX}/hosted/{relative}"] = EntrySpec(
            "file", mode, data=hosted[relative]
        )
    for destination, raw in helper_bytes().items():
        entries[f"{release.CAPSULE_PREFIX}/{destination}"] = EntrySpec(
            "file", 0o555, data=raw
        )
    assert entries[client].data.startswith(b"\x7fELF")
    return entries


def files_entries() -> dict[str, EntrySpec]:
    return {
        "bin": EntrySpec("symlink", 0o777, linkname="usr/bin"),
        "etc": EntrySpec("directory", 0o755),
        "etc/ssl": EntrySpec("directory", 0o755),
        "etc/ssl/certs": EntrySpec("directory", 0o755),
        "etc/ssl/certs/ca-certificates.crt": EntrySpec(
            "file", 0o644, data=b"certificate bundle"
        ),
        release.FILES_RECORD_PATH: EntrySpec(
            "file",
            0o444,
            data=release.canonical_json(
                {"schemaVersion": 1, "sourceRevision": SOURCE}
            ),
        ),
        "usr/local/bin/portablefs-files": EntrySpec(
            "file", 0o555, data=b"\x7fELFportablefs-files"
        ),
        "request-trust": EntrySpec("directory", 0o755),
        "usr": EntrySpec("directory", 0o755),
        "usr/bin": EntrySpec("directory", 0o755),
        "usr/bin/curl": EntrySpec("file", 0o755, data=b"\x7fELFcurl"),
        "usr/bin/dash": EntrySpec("file", 0o755, data=b"\x7fELFdash"),
        "usr/bin/sh": EntrySpec("symlink", 0o777, linkname="dash"),
        "usr/bin/tini": EntrySpec("file", 0o755, data=b"\x7fELFtini"),
        "usr/local": EntrySpec("directory", 0o755),
        "usr/local/bin": EntrySpec("directory", 0o755),
        "usr/local/share": EntrySpec("directory", 0o755),
        "usr/local/share/portablefs": EntrySpec("directory", 0o755),
        "var": EntrySpec("directory", 0o755),
        "var/lib": EntrySpec("directory", 0o755),
        "var/lib/portablefs-files": EntrySpec(
            "directory", 0o700, uid=200102, gid=200102
        ),
    }


def tar_bytes(entries: dict[str, EntrySpec]) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for name, spec in entries.items():
            member = tarfile.TarInfo(name + ("/" if spec.kind == "directory" else ""))
            member.mode = spec.mode
            member.uid = spec.uid
            member.gid = spec.gid
            member.mtime = 1_777_777_777
            if spec.kind == "directory":
                member.type = tarfile.DIRTYPE
                archive.addfile(member)
            elif spec.kind == "file":
                member.type = tarfile.REGTYPE
                member.size = len(spec.data)
                archive.addfile(member, io.BytesIO(spec.data))
            elif spec.kind == "symlink":
                member.type = tarfile.SYMTYPE
                member.linkname = spec.linkname
                archive.addfile(member)
            elif spec.kind == "hardlink":
                member.type = tarfile.LNKTYPE
                member.linkname = spec.linkname
                archive.addfile(member)
            else:
                member.type = tarfile.CHRTYPE
                archive.addfile(member)
    return output.getvalue()


def runtime_config(kind: str) -> dict:
    if kind == "release":
        return {
            "Env": ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],
            "Labels": {
                "io.opensteer.portablefs.release-record": release.CAPSULE_RECORD_CONTAINER_PATH,
                "org.opencontainers.image.revision": SOURCE,
                "org.opencontainers.image.source": release.REPOSITORY_URL,
                "org.opencontainers.image.version": RELEASE_ID,
            },
            "WorkingDir": "/",
        }
    return {
        "Entrypoint": ["/usr/bin/tini", "--", "/usr/local/bin/portablefs-files"],
        "Env": [
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "DEBIAN_FRONTEND=noninteractive",
        ],
        "ExposedPorts": {"4315/tcp": {}},
        "Labels": {
            "io.opensteer.portablefs.release-record": f"/{release.FILES_RECORD_PATH}",
            "org.opencontainers.image.revision": SOURCE,
            "org.opencontainers.image.source": release.REPOSITORY_URL,
            "org.opencontainers.image.version": SOURCE,
        },
        "User": "200102:200102",
        "WorkingDir": "/",
    }


def write_fixture(
    root: Path,
    kind: str,
    *,
    entries: dict[str, EntrySpec] | None = None,
    runtime: dict | None = None,
    index: bool = False,
    extra_layers: int = 0,
) -> Fixture:
    entries = copy.deepcopy(entries or (capsule_entries() if kind == "release" else files_entries()))
    raw_tar = tar_bytes(entries)
    compressed = gzip.compress(raw_tar, mtime=0)
    diff_id = release.sha256_bytes(raw_tar)
    layer_digest = release.sha256_bytes(compressed)

    config = {
        "architecture": "amd64",
        "config": copy.deepcopy(runtime or runtime_config(kind)),
        "created": "2026-08-23T00:00:00Z",
        "history": [{"created_by": "COPY", "empty_layer": False}],
        "os": "linux",
        "rootfs": {"diff_ids": [diff_id], "type": "layers"},
    }
    layers = [
        {
            "digest": layer_digest,
            "mediaType": release.OCI_LAYER_GZIP,
            "size": len(compressed),
        }
    ]
    for number in range(extra_layers):
        extra_tar = tar_bytes({f"extra-{number}": EntrySpec("file", 0o444, data=b"x")})
        extra_compressed = gzip.compress(extra_tar, mtime=0)
        extra_digest = release.sha256_bytes(extra_compressed)
        layers.append(
            {
                "digest": extra_digest,
                "mediaType": release.OCI_LAYER_GZIP,
                "size": len(extra_compressed),
            }
        )
        config["rootfs"]["diff_ids"].append(release.sha256_bytes(extra_tar))
        config["history"].append({"created_by": "COPY", "empty_layer": False})

    config_raw = release.canonical_json(config)
    config_digest = release.sha256_bytes(config_raw)
    manifest_value = {
        "config": {
            "digest": config_digest,
            "mediaType": release.OCI_CONFIG,
            "size": len(config_raw),
        },
        "layers": layers,
        "mediaType": release.OCI_MANIFEST,
        "schemaVersion": 2,
    }
    manifest_raw = release.canonical_json(manifest_value)
    manifest_digest = release.sha256_bytes(manifest_raw)
    if index:
        root_value = {
            "manifests": [
                {
                    "digest": manifest_digest,
                    "mediaType": release.OCI_MANIFEST,
                    "platform": {"architecture": "amd64", "os": "linux"},
                    "size": len(manifest_raw),
                }
            ],
            "mediaType": release.OCI_INDEX,
            "schemaVersion": 2,
        }
        root_raw = release.canonical_json(root_value)
    else:
        root_raw = manifest_raw

    blobs = root / "blobs"
    blobs.mkdir()
    (blobs / config_digest.removeprefix("sha256:")).write_bytes(config_raw)
    (blobs / layer_digest.removeprefix("sha256:")).write_bytes(compressed)
    for descriptor in layers[1:]:
        # Recreate the deterministic extra layer by its ordinal.
        number = layers.index(descriptor) - 1
        extra_tar = tar_bytes({f"extra-{number}": EntrySpec("file", 0o444, data=b"x")})
        (blobs / descriptor["digest"].removeprefix("sha256:")).write_bytes(
            gzip.compress(extra_tar, mtime=0)
        )
    root_manifest = root / "root.json"
    manifest_path = root / "manifest.json"
    root_manifest.write_bytes(root_raw)
    manifest_path.write_bytes(manifest_raw)
    return Fixture(
        root=root,
        root_manifest=root_manifest,
        manifest=manifest_path,
        blobs=blobs,
        digest=release.sha256_bytes(root_raw),
        entries=entries,
        config=config,
    )


def verify_fixture(fixture: Fixture, kind: str):
    return release.verify_remote_image(
        kind=kind,
        source=SOURCE,
        expected_digest=fixture.digest,
        root_manifest=fixture.root_manifest,
        manifest_path=fixture.manifest,
        blobs=fixture.blobs,
        files_image=FILES_IMAGE if kind == "release" else None,
        source_root=release.ROOT,
    )


class ReleaseRegistryTests(unittest.TestCase):
    def fixture(self, kind: str, **kwargs) -> tuple[tempfile.TemporaryDirectory, Fixture]:
        temporary = tempfile.TemporaryDirectory(prefix="portablefs-registry-test-")
        return temporary, write_fixture(Path(temporary.name), kind, **kwargs)

    def assert_fixture_rejected(self, kind: str, pattern: str, **kwargs) -> None:
        temporary, fixture = self.fixture(kind, **kwargs)
        try:
            with self.assertRaisesRegex(release.ReleaseError, pattern):
                verify_fixture(fixture, kind)
        finally:
            temporary.cleanup()

    def test_exact_release_capsule_direct_manifest(self) -> None:
        temporary, fixture = self.fixture("release")
        try:
            record = verify_fixture(fixture, "release")
            self.assertEqual(record["release"]["releaseId"], RELEASE_ID)
        finally:
            temporary.cleanup()

    def test_release_can_derive_the_record_selected_files_image(self) -> None:
        temporary, fixture = self.fixture("release")
        try:
            record = release.verify_remote_image(
                kind="release",
                source=SOURCE,
                expected_digest=fixture.digest,
                root_manifest=fixture.root_manifest,
                manifest_path=fixture.manifest,
                blobs=fixture.blobs,
                source_root=release.ROOT,
            )
            self.assertEqual(
                record["components"]["portablefs-files"]["image"], FILES_IMAGE
            )
        finally:
            temporary.cleanup()

    def test_infra_record_is_the_exact_canonical_schema(self) -> None:
        inner = release.expected_release_record(
            SOURCE,
            RELEASE_ID,
            FILES_IMAGE,
            f"sha256:{'c' * 64}",
        )
        registry_record = f"{release.RELEASE_REPOSITORY}@sha256:{'d' * 64}"
        external = release.infra_release_record(inner, registry_record)
        self.assertEqual(
            release.canonical_json(external),
            (
                '{"components":{"portablefs-files":{"image":"'
                + FILES_IMAGE
                + '"}},"release":{"clientSha256":"sha256:'
                + "c" * 64
                + '","registryRecord":"'
                + registry_record
                + '","releaseId":"'
                + RELEASE_ID
                + '","sourceRevision":"'
                + SOURCE
                + '"},"repository":"steerlabs/portablefs","schemaVersion":2}\n'
            ).encode(),
        )

    def test_infra_record_rejects_a_tag_reference(self) -> None:
        inner = release.expected_release_record(
            SOURCE,
            RELEASE_ID,
            FILES_IMAGE,
            f"sha256:{'c' * 64}",
        )
        with self.assertRaisesRegex(release.ReleaseError, "exact digest reference"):
            release.infra_release_record(
                inner, f"{release.RELEASE_REPOSITORY}:sha-{SOURCE}"
            )

    def test_registry_index_is_rejected(self) -> None:
        temporary, fixture = self.fixture("release", index=True)
        try:
            with self.assertRaisesRegex(release.ReleaseError, "one direct OCI image manifest"):
                verify_fixture(fixture, "release")
        finally:
            temporary.cleanup()

    def test_exact_files_image(self) -> None:
        temporary, fixture = self.fixture("files")
        try:
            self.assertIsNone(verify_fixture(fixture, "files"))
        finally:
            temporary.cleanup()

    def test_capsule_rejects_extra_member(self) -> None:
        entries = capsule_entries()
        entries[f"{release.CAPSULE_PREFIX}/surprise"] = EntrySpec("file", 0o444, data=b"x")
        self.assert_fixture_rejected("release", "membership is not exact", entries=entries)

    def test_capsule_rejects_symlink(self) -> None:
        entries = capsule_entries()
        target = f"{release.CAPSULE_PREFIX}/hosted/bin/portablefs"
        entries[target] = EntrySpec("symlink", 0o777, linkname="portablefs-manager")
        self.assert_fixture_rejected("release", "member is unsafe", entries=entries)

    def test_capsule_rejects_hardlink(self) -> None:
        entries = capsule_entries()
        target = f"{release.CAPSULE_PREFIX}/hosted/bin/portablefs"
        entries[target] = EntrySpec("hardlink", 0o755, linkname="portablefs-manager")
        self.assert_fixture_rejected("release", "member is unsafe", entries=entries)

    def test_capsule_rejects_path_traversal(self) -> None:
        entries = capsule_entries()
        entries[f"{release.CAPSULE_PREFIX}/../escape"] = EntrySpec("file", 0o444, data=b"x")
        self.assert_fixture_rejected("release", "noncanonical path", entries=entries)

    def test_capsule_rejects_wrong_mode(self) -> None:
        entries = capsule_entries()
        entries[release.CAPSULE_RECORD_PATH].mode = 0o644
        self.assert_fixture_rejected("release", "member is unsafe", entries=entries)

    def test_capsule_rejects_nonroot_owner(self) -> None:
        entries = capsule_entries()
        entries[release.CAPSULE_RECORD_PATH].uid = 1000
        self.assert_fixture_rejected("release", "member is unsafe", entries=entries)

    def test_capsule_rejects_unknown_record_key(self) -> None:
        entries = capsule_entries()
        record = json.loads(entries[release.CAPSULE_RECORD_PATH].data)
        record["fallback"] = True
        entries[release.CAPSULE_RECORD_PATH].data = release.canonical_json(record)
        self.assert_fixture_rejected("release", "keys are not exact", entries=entries)

    def test_capsule_rejects_boolean_schema_version(self) -> None:
        entries = capsule_entries()
        record = json.loads(entries[release.CAPSULE_RECORD_PATH].data)
        record["schemaVersion"] = True
        entries[release.CAPSULE_RECORD_PATH].data = release.canonical_json(record)
        self.assert_fixture_rejected(
            "release", "schemaVersion must be 1", entries=entries
        )

    def test_capsule_rejects_noncanonical_record(self) -> None:
        entries = capsule_entries()
        record = json.loads(entries[release.CAPSULE_RECORD_PATH].data)
        entries[release.CAPSULE_RECORD_PATH].data = (json.dumps(record, indent=2) + "\n").encode()
        self.assert_fixture_rejected("release", "not canonical", entries=entries)

    def test_capsule_rejects_client_digest_mismatch(self) -> None:
        entries = capsule_entries()
        record = json.loads(entries[release.CAPSULE_RECORD_PATH].data)
        record["release"]["clientSha256"] = f"sha256:{'c' * 64}"
        entries[release.CAPSULE_RECORD_PATH].data = release.canonical_json(record)
        self.assert_fixture_rejected("release", "client digest differs", entries=entries)

    def test_capsule_rejects_helper_drift(self) -> None:
        entries = capsule_entries()
        helper = f"{release.CAPSULE_PREFIX}/tools/deploy/gcp/verify-hosted-release.sh"
        entries[helper].data += b"\nchanged\n"
        self.assert_fixture_rejected("release", "helper differs", entries=entries)

    def test_capsule_rejects_multiple_layers(self) -> None:
        self.assert_fixture_rejected("release", "exactly one filesystem layer", extra_layers=1)

    def test_capsule_rejects_dangerous_runtime_config(self) -> None:
        runtime = runtime_config("release")
        runtime["Entrypoint"] = ["/bin/sh"]
        self.assert_fixture_rejected("release", "runtime config is not exact", runtime=runtime)

    def test_files_rejects_dangerous_environment(self) -> None:
        runtime = runtime_config("files")
        runtime["Env"].append("NODE_OPTIONS=--require=/tmp/x")
        self.assert_fixture_rejected("files", "runtime config is not exact", runtime=runtime)

    def test_files_rejects_wrong_source_record(self) -> None:
        entries = files_entries()
        entries[release.FILES_RECORD_PATH].data = release.canonical_json(
            {"schemaVersion": 1, "sourceRevision": "c" * 40}
        )
        self.assert_fixture_rejected("files", "does not name the exact source", entries=entries)

    def test_files_rejects_binary_symlink(self) -> None:
        entries = files_entries()
        entries["usr/local/bin/portablefs-files"] = EntrySpec(
            "symlink", 0o777, linkname="/tmp/payload"
        )
        self.assert_fixture_rejected("files", "rootfs member is unsafe", entries=entries)

    def test_root_digest_must_match_registry(self) -> None:
        temporary, fixture = self.fixture("release")
        try:
            fixture.root_manifest.write_bytes(fixture.root_manifest.read_bytes() + b"\n")
            with self.assertRaisesRegex(release.ReleaseError, "registry digest"):
                verify_fixture(fixture, "release")
        finally:
            temporary.cleanup()

    def test_layer_blob_digest_must_match_descriptor(self) -> None:
        temporary, fixture = self.fixture("release")
        try:
            manifest = json.loads(fixture.manifest.read_bytes())
            layer = fixture.blobs / manifest["layers"][0]["digest"].removeprefix("sha256:")
            layer.write_bytes(layer.read_bytes() + b"corrupt")
            with self.assertRaisesRegex(release.ReleaseError, "size differs"):
                verify_fixture(fixture, "release")
        finally:
            temporary.cleanup()

    def test_diff_id_must_match_decompressed_layer(self) -> None:
        temporary, fixture = self.fixture("release")
        try:
            config_digest = json.loads(fixture.manifest.read_bytes())["config"]["digest"]
            config_path = fixture.blobs / config_digest.removeprefix("sha256:")
            config = json.loads(config_path.read_bytes())
            config["rootfs"]["diff_ids"][0] = f"sha256:{'d' * 64}"
            replacement = release.canonical_json(config)
            replacement_digest = release.sha256_bytes(replacement)
            replacement_path = fixture.blobs / replacement_digest.removeprefix("sha256:")
            replacement_path.write_bytes(replacement)
            manifest = json.loads(fixture.manifest.read_bytes())
            manifest["config"] = {
                "digest": replacement_digest,
                "mediaType": release.OCI_CONFIG,
                "size": len(replacement),
            }
            manifest_raw = release.canonical_json(manifest)
            fixture.manifest.write_bytes(manifest_raw)
            fixture.root_manifest.write_bytes(manifest_raw)
            fixture.digest = release.sha256_bytes(manifest_raw)
            with self.assertRaisesRegex(release.ReleaseError, "uncompressed digest"):
                verify_fixture(fixture, "release")
        finally:
            temporary.cleanup()

    def test_config_rejects_wrong_platform(self) -> None:
        temporary, fixture = self.fixture("release")
        try:
            manifest = json.loads(fixture.manifest.read_bytes())
            config_digest = manifest["config"]["digest"]
            config_path = fixture.blobs / config_digest.removeprefix("sha256:")
            config = json.loads(config_path.read_bytes())
            config["architecture"] = "arm64"
            replacement = release.canonical_json(config)
            replacement_digest = release.sha256_bytes(replacement)
            (fixture.blobs / replacement_digest.removeprefix("sha256:")).write_bytes(replacement)
            manifest["config"] = {
                "digest": replacement_digest,
                "mediaType": release.OCI_CONFIG,
                "size": len(replacement),
            }
            raw = release.canonical_json(manifest)
            fixture.manifest.write_bytes(raw)
            fixture.root_manifest.write_bytes(raw)
            fixture.digest = release.sha256_bytes(raw)
            with self.assertRaisesRegex(release.ReleaseError, "linux/amd64"):
                verify_fixture(fixture, "release")
        finally:
            temporary.cleanup()

    def test_blob_list_rejects_duplicate_layer_digest(self) -> None:
        temporary, fixture = self.fixture("release")
        try:
            manifest = json.loads(fixture.manifest.read_bytes())
            manifest["layers"].append(copy.deepcopy(manifest["layers"][0]))
            fixture.manifest.write_bytes(release.canonical_json(manifest))
            with self.assertRaisesRegex(release.ReleaseError, "repeats a blob digest"):
                release.list_blob_digests(fixture.manifest)
        finally:
            temporary.cleanup()

    def test_descriptor_rejects_boolean_size(self) -> None:
        with self.assertRaisesRegex(release.ReleaseError, "invalid size"):
            release._descriptor(
                {
                    "digest": f"sha256:{'a' * 64}",
                    "mediaType": release.OCI_LAYER_GZIP,
                    "size": True,
                },
                "adversarial descriptor",
            )

    def test_blob_list_enforces_total_compressed_bound(self) -> None:
        temporary, fixture = self.fixture("files")
        try:
            with patch.object(release, "MAX_IMAGE_COMPRESSED_BYTES", 1):
                with self.assertRaisesRegex(release.ReleaseError, "compressed byte bound"):
                    release.list_blob_descriptors(fixture.manifest)
        finally:
            temporary.cleanup()

    def test_member_byte_bound_is_enforced(self) -> None:
        entries = capsule_entries()
        entries[f"{release.CAPSULE_PREFIX}/hosted/bin/portablefs"].data = b"\x7fELF12345"
        temporary, fixture = self.fixture("release", entries=entries)
        try:
            with patch.object(release, "MAX_CAPSULE_FILE_BYTES", 8):
                with self.assertRaisesRegex(release.ReleaseError, "byte bound"):
                    verify_fixture(fixture, "release")
        finally:
            temporary.cleanup()


if __name__ == "__main__":
    unittest.main(verbosity=2)
