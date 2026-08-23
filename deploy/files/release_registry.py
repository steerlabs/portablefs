#!/usr/bin/env python3
"""Build and verify the immutable PortableFS staging release artifacts.

This module deliberately has no registry client.  The workflow fetches every
descriptor and blob with a pinned `crane`, then this code verifies those bytes
offline.  That separation keeps authentication out of the release parser and
makes every trust decision directly unit-testable.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import posixpath
import re
import stat
import subprocess
import sys
import tarfile
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[2]
REPOSITORY_ID = "1313214092"
REPOSITORY_NAME = "steerlabs/portablefs"
REPOSITORY_URL = "https://github.com/steerlabs/portablefs"
WORKFLOW_PATH = ".github/workflows/files-image.yml"
WORKFLOW_REF = "refs/heads/main"
REGISTRY = "us-west1-docker.pkg.dev/opensteer-admin/portablefs-releases"
FILES_REPOSITORY = f"{REGISTRY}/portablefs-files"
RELEASE_REPOSITORY = f"{REGISTRY}/portablefs-release"
FILES_RECORD_PATH = "usr/local/share/portablefs/release.json"
CAPSULE_PREFIX = "opensteer-portablefs-release"
CAPSULE_RECORD_PATH = f"{CAPSULE_PREFIX}/release.json"
CAPSULE_RECORD_CONTAINER_PATH = f"/{CAPSULE_RECORD_PATH}"

COMMIT = re.compile(r"^[0-9a-f]{40}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
FILES_IMAGE = re.compile(
    rf"^{re.escape(FILES_REPOSITORY)}@sha256:[0-9a-f]{{64}}$"
)
RELEASE_IMAGE = re.compile(
    rf"^{re.escape(RELEASE_REPOSITORY)}@sha256:[0-9a-f]{{64}}$"
)
RELEASE_ID = re.compile(r"^pfs-hosted-[0-9]{8}-([0-9a-f]{12})$")

OCI_INDEX = "application/vnd.oci.image.index.v1+json"
OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
OCI_CONFIG = "application/vnd.oci.image.config.v1+json"
OCI_LAYER_GZIP = "application/vnd.oci.image.layer.v1.tar+gzip"

MAX_JSON_BYTES = 2 * 1024 * 1024
MAX_CONFIG_BYTES = 4 * 1024 * 1024
MAX_SAFE_JSON_INTEGER = (1 << 53) - 1
MAX_LAYER_COMPRESSED_BYTES = 512 * 1024 * 1024
MAX_LAYER_UNCOMPRESSED_BYTES = 1024 * 1024 * 1024
MAX_IMAGE_COMPRESSED_BYTES = 1024 * 1024 * 1024
MAX_IMAGE_UNCOMPRESSED_BYTES = 2 * 1024 * 1024 * 1024
MAX_LAYER_ENTRIES = 250_000
MAX_LAYERS = 8
MAX_CAPSULE_FILE_BYTES = 128 * 1024 * 1024
MAX_CAPSULE_BYTES = 512 * 1024 * 1024


class ReleaseError(RuntimeError):
    """A release artifact contradicts the closed publication contract."""


HOSTED_MODES: dict[str, int] = {
    "architecture": 0o644,
    "bin/portablefs": 0o755,
    "bin/portablefs-archiver": 0o755,
    "bin/portablefs-authority": 0o755,
    "bin/portablefs-cell-agent": 0o755,
    "bin/portablefs-hydrator": 0o755,
    "bin/portablefs-manager": 0o755,
    "libexec/portablefs-authority-launcher": 0o755,
    "libexec/portablefs-cell-helper": 0o755,
    "release-id": 0o644,
    "SHA256SUMS": 0o644,
    "source-commit": 0o644,
    "systemd/portablefs-archiver@.service": 0o644,
    "systemd/portablefs-authority@.service": 0o644,
    "systemd/portablefs-authority@.socket": 0o644,
    "systemd/portablefs-cell-agent@.service": 0o644,
    "systemd/portablefs-cell-helper@.service": 0o644,
    "systemd/portablefs-hydrator@.service": 0o644,
    "systemd/portablefs-manager.service": 0o644,
}

HELPERS: dict[str, str] = {
    "deploy/gcp/verify-hosted-release.sh": (
        "tools/deploy/gcp/verify-hosted-release.sh"
    ),
    "deploy/gcp/activate-hosted-release.sh": (
        "tools/deploy/gcp/activate-hosted-release.sh"
    ),
    "deploy/opensteer/manager-api.sh": "tools/deploy/opensteer/manager-api.sh",
    "deploy/opensteer/cell-authority-state.sh": (
        "tools/deploy/opensteer/cell-authority-state.sh"
    ),
    "deploy/opensteer/release-inventory.mjs": (
        "tools/deploy/opensteer/release-inventory.mjs"
    ),
}

CAPSULE_FILE_MODES: dict[str, int] = {
    CAPSULE_RECORD_PATH: 0o444,
    **{
        f"{CAPSULE_PREFIX}/hosted/{relative}": mode
        for relative, mode in HOSTED_MODES.items()
    },
    **{
        f"{CAPSULE_PREFIX}/{destination}": 0o555
        for destination in HELPERS.values()
    },
}

CAPSULE_DIRECTORIES = frozenset(
    {
        CAPSULE_PREFIX,
        f"{CAPSULE_PREFIX}/hosted",
        f"{CAPSULE_PREFIX}/hosted/bin",
        f"{CAPSULE_PREFIX}/hosted/libexec",
        f"{CAPSULE_PREFIX}/hosted/systemd",
        f"{CAPSULE_PREFIX}/tools",
        f"{CAPSULE_PREFIX}/tools/deploy",
        f"{CAPSULE_PREFIX}/tools/deploy/gcp",
        f"{CAPSULE_PREFIX}/tools/deploy/opensteer",
    }
)


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ReleaseError(f"JSON repeats key {key!r}")
        result[key] = value
    return result


def strict_json(raw: bytes, label: str, maximum: int = MAX_JSON_BYTES) -> Any:
    if len(raw) > maximum:
        raise ReleaseError(f"{label} exceeds the {maximum}-byte bound")

    def reject_constant(value: str) -> None:
        raise ReleaseError(f"{label} contains non-finite JSON number {value}")

    try:
        return json.loads(
            raw,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ReleaseError(f"{label} is not valid UTF-8 JSON") from error


def canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
        + "\n"
    ).encode()


def sha256_bytes(raw: bytes) -> str:
    return f"sha256:{hashlib.sha256(raw).hexdigest()}"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return f"sha256:{digest.hexdigest()}"


def bounded_read(path: Path, maximum: int, label: str) -> bytes:
    try:
        metadata = path.lstat()
    except FileNotFoundError as error:
        raise ReleaseError(f"missing {label}") from error
    if not stat.S_ISREG(metadata.st_mode):
        raise ReleaseError(f"{label} is not one regular file")
    size = metadata.st_size
    if size > maximum:
        raise ReleaseError(f"{label} exceeds the {maximum}-byte bound")
    raw = path.read_bytes()
    if len(raw) != size:
        raise ReleaseError(f"{label} changed while it was read")
    return raw


def bounded_stdin_copy(output: Path, maximum: int, exact_size: int | None) -> None:
    """Copy a registry response without ever materializing bytes past its bound."""
    if maximum <= 0 or maximum > MAX_IMAGE_COMPRESSED_BYTES:
        raise ReleaseError("stream byte bound is outside the allowed range")
    if exact_size is not None and (exact_size <= 0 or exact_size > maximum):
        raise ReleaseError("stream exact size is outside its byte bound")
    if (
        output.exists()
        or output.is_symlink()
        or not output.parent.is_dir()
        or output.parent.is_symlink()
    ):
        raise ReleaseError("bounded stream output path is unsafe")
    total = 0
    try:
        with output.open("xb") as destination:
            while chunk := sys.stdin.buffer.read(min(1024 * 1024, maximum - total + 1)):
                total += len(chunk)
                if total > maximum:
                    raise ReleaseError("registry response exceeds its byte bound")
                destination.write(chunk)
        if exact_size is not None and total != exact_size:
            raise ReleaseError("registry response differs from its descriptor size")
    except BaseException:
        output.unlink(missing_ok=True)
        raise


def exact_keys(value: Any, expected: Iterable[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ReleaseError(f"{label} must be an object")
    expected_set = set(expected)
    if set(value) != expected_set:
        missing = sorted(expected_set - set(value))
        unknown = sorted(set(value) - expected_set)
        raise ReleaseError(
            f"{label} keys are not exact (missing={missing}, unknown={unknown})"
        )
    return value


def _validate_identity(source: str, release_id: str) -> None:
    if not COMMIT.fullmatch(source) or source == "0" * 40:
        raise ReleaseError("source revision must be one full nonzero lowercase commit")
    match = RELEASE_ID.fullmatch(release_id)
    if match is None or match.group(1) != source[:12]:
        raise ReleaseError("release ID must name the first 12 source revision bytes")


def expected_release_record(
    source: str, release_id: str, files_image: str, client_sha256: str
) -> dict[str, Any]:
    _validate_identity(source, release_id)
    if FILES_IMAGE.fullmatch(files_image) is None:
        raise ReleaseError("portablefs-files image must use the exact registry and digest")
    if DIGEST.fullmatch(client_sha256) is None:
        raise ReleaseError("client SHA-256 is invalid")
    return {
        "components": {"portablefs-files": {"image": files_image}},
        "release": {
            "clientSha256": client_sha256,
            "releaseId": release_id,
            "sourceRevision": source,
        },
        "repository": {"id": REPOSITORY_ID, "name": REPOSITORY_NAME},
        "schemaVersion": 1,
        "workflow": {"path": WORKFLOW_PATH, "ref": WORKFLOW_REF},
    }


def validate_release_record(
    raw: bytes,
    *,
    expected_source: str | None = None,
    expected_files_image: str | None = None,
) -> dict[str, Any]:
    value = strict_json(raw, "capsule release.json")
    if raw != canonical_json(value):
        raise ReleaseError("capsule release.json is not canonical compact sorted JSON")
    record = exact_keys(
        value,
        ["components", "release", "repository", "schemaVersion", "workflow"],
        "capsule release.json",
    )
    if type(record["schemaVersion"]) is not int or record["schemaVersion"] != 1:
        raise ReleaseError("capsule release.json schemaVersion must be 1")
    repository = exact_keys(record["repository"], ["id", "name"], "repository")
    if repository != {"id": REPOSITORY_ID, "name": REPOSITORY_NAME}:
        raise ReleaseError("capsule repository identity is not PortableFS")
    workflow = exact_keys(record["workflow"], ["path", "ref"], "workflow")
    if workflow != {"path": WORKFLOW_PATH, "ref": WORKFLOW_REF}:
        raise ReleaseError("capsule publication workflow is not main files-image")
    components = exact_keys(record["components"], ["portablefs-files"], "components")
    files = exact_keys(components["portablefs-files"], ["image"], "portablefs-files")
    files_image = files["image"]
    if not isinstance(files_image, str) or FILES_IMAGE.fullmatch(files_image) is None:
        raise ReleaseError("capsule portablefs-files image is not digest pinned")
    release = exact_keys(
        record["release"],
        ["clientSha256", "releaseId", "sourceRevision"],
        "release",
    )
    source = release["sourceRevision"]
    release_id = release["releaseId"]
    client_sha256 = release["clientSha256"]
    if not all(isinstance(item, str) for item in (source, release_id, client_sha256)):
        raise ReleaseError("capsule release identity fields must be strings")
    _validate_identity(source, release_id)
    if DIGEST.fullmatch(client_sha256) is None:
        raise ReleaseError("capsule client SHA-256 is invalid")
    if expected_source is not None and source != expected_source:
        raise ReleaseError("capsule source revision does not match the requested source")
    if expected_files_image is not None and files_image != expected_files_image:
        raise ReleaseError("capsule portablefs-files digest differs from the verified image")
    return record


def infra_release_record(
    record: dict[str, Any], registry_record: str
) -> dict[str, Any]:
    """Translate one verified inner record into infra's release state schema."""
    if RELEASE_IMAGE.fullmatch(registry_record) is None:
        raise ReleaseError("aggregate registry record must be the exact digest reference")
    # Re-canonicalizing and validating here prevents this boundary helper from
    # becoming a second, looser interpretation of the inner schema.
    verified = validate_release_record(canonical_json(record))
    release = verified["release"]
    return {
        "components": verified["components"],
        "release": {
            "clientSha256": release["clientSha256"],
            "registryRecord": registry_record,
            "releaseId": release["releaseId"],
            "sourceRevision": release["sourceRevision"],
        },
        "repository": REPOSITORY_NAME,
        "schemaVersion": 2,
    }


def validate_files_record(raw: bytes, expected_source: str) -> None:
    value = strict_json(raw, "portablefs-files release.json")
    if raw != canonical_json(value):
        raise ReleaseError("portablefs-files release.json is not canonical")
    record = exact_keys(value, ["schemaVersion", "sourceRevision"], "files release.json")
    if (
        type(record["schemaVersion"]) is not int
        or record != {"schemaVersion": 1, "sourceRevision": expected_source}
    ):
        raise ReleaseError("portablefs-files release.json does not name the exact source")


def _regular_file(path: Path, mode: int, label: str) -> bytes:
    try:
        metadata = path.lstat()
    except FileNotFoundError as error:
        raise ReleaseError(f"missing {label}") from error
    if not stat.S_ISREG(metadata.st_mode):
        raise ReleaseError(f"{label} is not a regular file")
    if stat.S_IMODE(metadata.st_mode) != mode:
        raise ReleaseError(
            f"{label} mode is {stat.S_IMODE(metadata.st_mode):04o}, expected {mode:04o}"
        )
    if metadata.st_size > MAX_CAPSULE_FILE_BYTES:
        raise ReleaseError(f"{label} exceeds the per-file bound")
    return path.read_bytes()


def _validate_checksum_manifest(hosted: Path) -> None:
    expected = sorted(relative for relative in HOSTED_MODES if relative != "SHA256SUMS")
    raw = _regular_file(hosted / "SHA256SUMS", 0o644, "hosted/SHA256SUMS")
    try:
        lines = raw.decode("ascii").splitlines()
    except UnicodeDecodeError as error:
        raise ReleaseError("hosted/SHA256SUMS is not ASCII") from error
    if len(lines) != len(expected):
        raise ReleaseError("hosted/SHA256SUMS membership count is not exact")
    actual_names: list[str] = []
    for line in lines:
        match = re.fullmatch(r"([0-9a-f]{64})  ([^\x00\r\n]+)", line)
        if match is None:
            raise ReleaseError("hosted/SHA256SUMS has a noncanonical line")
        digest, relative = match.groups()
        actual_names.append(relative)
        member = hosted / relative
        if sha256_file(member) != f"sha256:{digest}":
            raise ReleaseError(f"hosted checksum mismatch for {relative}")
    if actual_names != expected:
        raise ReleaseError("hosted/SHA256SUMS membership or ordering is not exact")


def verify_capsule_directory(
    directory: Path,
    *,
    expected_source: str | None = None,
    expected_files_image: str | None = None,
    source_root: Path = ROOT,
) -> dict[str, Any]:
    if not directory.is_dir() or directory.is_symlink():
        raise ReleaseError("capsule directory must be a real directory")
    expected_files = {
        relative.removeprefix(f"{CAPSULE_PREFIX}/"): mode
        for relative, mode in CAPSULE_FILE_MODES.items()
    }
    actual_files: dict[str, os.stat_result] = {}
    actual_directories: set[str] = set()
    total = 0
    for path in directory.rglob("*"):
        relative = path.relative_to(directory).as_posix()
        metadata = path.lstat()
        if stat.S_ISDIR(metadata.st_mode):
            actual_directories.add(relative)
            if stat.S_IMODE(metadata.st_mode) != 0o755:
                raise ReleaseError(f"capsule directory {relative} is not mode 0755")
        elif stat.S_ISREG(metadata.st_mode):
            actual_files[relative] = metadata
            total += metadata.st_size
        else:
            raise ReleaseError(f"capsule contains unsafe member {relative}")
    expected_directories = {
        relative.removeprefix(f"{CAPSULE_PREFIX}/")
        for relative in CAPSULE_DIRECTORIES
        if relative != CAPSULE_PREFIX
    }
    if actual_directories != expected_directories:
        raise ReleaseError("capsule directory membership is not exact")
    if set(actual_files) != set(expected_files):
        raise ReleaseError("capsule file membership is not exact")
    if total > MAX_CAPSULE_BYTES:
        raise ReleaseError("capsule exceeds the total byte bound")
    for relative, expected_mode in expected_files.items():
        metadata = actual_files[relative]
        if stat.S_IMODE(metadata.st_mode) != expected_mode:
            raise ReleaseError(f"capsule member {relative} has the wrong mode")
        if metadata.st_size > MAX_CAPSULE_FILE_BYTES:
            raise ReleaseError(f"capsule member {relative} exceeds its byte bound")

    record_raw = (directory / "release.json").read_bytes()
    record = validate_release_record(
        record_raw,
        expected_source=expected_source,
        expected_files_image=expected_files_image,
    )
    release = record["release"]
    hosted = directory / "hosted"
    if (hosted / "source-commit").read_bytes() != (
        release["sourceRevision"] + "\n"
    ).encode():
        raise ReleaseError("hosted source-commit differs from release.json")
    if (hosted / "release-id").read_bytes() != (release["releaseId"] + "\n").encode():
        raise ReleaseError("hosted release-id differs from release.json")
    if (hosted / "architecture").read_bytes() != b"amd64\n":
        raise ReleaseError("hosted architecture is not amd64")
    if sha256_file(hosted / "bin/portablefs") != release["clientSha256"]:
        raise ReleaseError("hosted client bytes differ from release.json")
    _validate_checksum_manifest(hosted)
    for source_relative, destination_relative in HELPERS.items():
        source = source_root / source_relative
        destination = directory / destination_relative
        if not source.is_file() or source.is_symlink():
            raise ReleaseError(f"source helper is missing or unsafe: {source_relative}")
        if source.read_bytes() != destination.read_bytes():
            raise ReleaseError(f"capsule helper differs from source: {source_relative}")
    return record


def assemble_capsule(
    hosted: Path,
    output: Path,
    source: str,
    release_id: str,
    files_image: str,
    source_root: Path = ROOT,
) -> None:
    _validate_identity(source, release_id)
    if FILES_IMAGE.fullmatch(files_image) is None:
        raise ReleaseError("portablefs-files image must be digest pinned")
    if output.exists():
        raise ReleaseError("capsule output already exists")
    if not hosted.is_dir() or hosted.is_symlink():
        raise ReleaseError("hosted release path must be a real directory")
    subprocess.run(
        [str(source_root / "deploy/gcp/verify-hosted-release.sh"), str(hosted)],
        check=True,
        timeout=300,
    )
    if (hosted / "source-commit").read_text() != f"{source}\n":
        raise ReleaseError("hosted release does not name the requested source")
    if (hosted / "release-id").read_text() != f"{release_id}\n":
        raise ReleaseError("hosted release does not name the requested release ID")

    output.mkdir(mode=0o755)
    hosted_output = output / "hosted"
    hosted_output.mkdir(mode=0o755)
    for relative, mode in HOSTED_MODES.items():
        source_path = hosted / relative
        raw = _regular_file(source_path, mode, f"hosted/{relative}")
        destination = hosted_output / relative
        destination.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        destination.write_bytes(raw)
        destination.chmod(mode)

    for source_relative, destination_relative in HELPERS.items():
        source_path = source_root / source_relative
        raw = _regular_file(
            source_path,
            stat.S_IMODE(source_path.lstat().st_mode),
            f"source helper {source_relative}",
        )
        destination = output / destination_relative
        destination.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        destination.write_bytes(raw)
        destination.chmod(0o555)

    client_sha256 = sha256_file(hosted_output / "bin/portablefs")
    record = expected_release_record(source, release_id, files_image, client_sha256)
    (output / "release.json").write_bytes(canonical_json(record))
    (output / "release.json").chmod(0o444)
    verify_capsule_directory(
        output,
        expected_source=source,
        expected_files_image=files_image,
        source_root=source_root,
    )


def _safe_tar_path(name: str) -> str:
    if "\x00" in name or "\\" in name or name.startswith("/"):
        raise ReleaseError(f"layer contains unsafe path {name!r}")
    normalized = name.rstrip("/")
    if normalized == "" or normalized != posixpath.normpath(normalized):
        raise ReleaseError(f"layer contains noncanonical path {name!r}")
    if any(part in ("", ".", "..") for part in normalized.split("/")):
        raise ReleaseError(f"layer contains traversal path {name!r}")
    return normalized


@dataclass(frozen=True)
class LayerEntry:
    kind: str
    mode: int
    uid: int
    gid: int
    size: int
    data: bytes | None
    linkname: str | None


def _decompress_layer(path: Path, expected_diff_id: str) -> Path:
    temporary = tempfile.NamedTemporaryFile(prefix="portablefs-layer-", delete=False)
    temporary_path = Path(temporary.name)
    digest = hashlib.sha256()
    total = 0
    try:
        with gzip.open(path, "rb") as compressed, temporary:
            while chunk := compressed.read(1024 * 1024):
                total += len(chunk)
                if total > MAX_LAYER_UNCOMPRESSED_BYTES:
                    raise ReleaseError("layer exceeds the uncompressed byte bound")
                digest.update(chunk)
                temporary.write(chunk)
    except ReleaseError:
        temporary_path.unlink(missing_ok=True)
        raise
    except (gzip.BadGzipFile, EOFError, OSError) as error:
        temporary_path.unlink(missing_ok=True)
        raise ReleaseError("layer is not one complete gzip stream") from error
    actual = f"sha256:{digest.hexdigest()}"
    if actual != expected_diff_id:
        temporary_path.unlink(missing_ok=True)
        raise ReleaseError("layer uncompressed digest differs from config rootfs")
    return temporary_path


def _read_layer(
    compressed_path: Path,
    expected_diff_id: str,
    *,
    capture_all: bool,
) -> tuple[list[tuple[str, LayerEntry]], int]:
    uncompressed = _decompress_layer(compressed_path, expected_diff_id)
    entries: list[tuple[str, LayerEntry]] = []
    seen: set[str] = set()
    total_files = 0
    try:
        uncompressed_size = uncompressed.stat().st_size
        with tarfile.open(uncompressed, mode="r:") as archive:
            members = archive.getmembers()
            if len(members) > MAX_LAYER_ENTRIES:
                raise ReleaseError("layer contains too many archive entries")
            for member in members:
                name = _safe_tar_path(member.name)
                if name in seen:
                    raise ReleaseError(f"layer repeats archive path {name}")
                seen.add(name)
                mode = member.mode & 0o7777
                if member.isdir():
                    entry = LayerEntry(
                        "directory", mode, member.uid, member.gid, 0, None, None
                    )
                elif member.isreg():
                    total_files += member.size
                    if total_files > MAX_LAYER_UNCOMPRESSED_BYTES:
                        raise ReleaseError("layer regular files exceed the byte bound")
                    capture = capture_all or name in {
                        FILES_RECORD_PATH,
                        "usr/local/bin/portablefs-files",
                    }
                    data = None
                    if capture:
                        if member.size > MAX_CAPSULE_FILE_BYTES:
                            raise ReleaseError(f"layer member {name} exceeds its byte bound")
                        extracted = archive.extractfile(member)
                        if extracted is None:
                            raise ReleaseError(f"layer member {name} cannot be read")
                        data = extracted.read(MAX_CAPSULE_FILE_BYTES + 1)
                        if len(data) != member.size:
                            raise ReleaseError(f"layer member {name} is truncated")
                    entry = LayerEntry(
                        "file", mode, member.uid, member.gid, member.size, data, None
                    )
                elif member.issym():
                    entry = LayerEntry(
                        "symlink",
                        mode,
                        member.uid,
                        member.gid,
                        0,
                        None,
                        member.linkname,
                    )
                elif member.islnk():
                    entry = LayerEntry(
                        "hardlink",
                        mode,
                        member.uid,
                        member.gid,
                        0,
                        None,
                        member.linkname,
                    )
                else:
                    entry = LayerEntry(
                        "special", mode, member.uid, member.gid, 0, None, None
                    )
                entries.append((name, entry))
    except (tarfile.TarError, OSError) as error:
        raise ReleaseError("layer is not a valid bounded tar archive") from error
    finally:
        uncompressed.unlink(missing_ok=True)
    return entries, uncompressed_size


def _descriptor(value: Any, label: str) -> dict[str, Any]:
    descriptor = exact_keys(value, ["digest", "mediaType", "size"], label)
    if descriptor["mediaType"] not in {OCI_CONFIG, OCI_LAYER_GZIP}:
        raise ReleaseError(f"{label} has an unsupported media type")
    if not isinstance(descriptor["digest"], str) or DIGEST.fullmatch(descriptor["digest"]) is None:
        raise ReleaseError(f"{label} has an invalid digest")
    if (
        type(descriptor["size"]) is not int
        or descriptor["size"] <= 0
        or descriptor["size"] > MAX_SAFE_JSON_INTEGER
    ):
        raise ReleaseError(f"{label} has an invalid size")
    return descriptor


def _blob_path(blobs: Path, digest: str) -> Path:
    return blobs / digest.removeprefix("sha256:")


def _verify_blob(blobs: Path, descriptor: dict[str, Any], label: str) -> Path:
    path = _blob_path(blobs, descriptor["digest"])
    try:
        metadata = path.lstat()
    except FileNotFoundError as error:
        raise ReleaseError(f"missing fetched {label} blob") from error
    if not stat.S_ISREG(metadata.st_mode):
        raise ReleaseError(f"fetched {label} blob is not one regular file")
    size = metadata.st_size
    if size != descriptor["size"]:
        raise ReleaseError(f"{label} blob size differs from its descriptor")
    if label == "config" and size > MAX_CONFIG_BYTES:
        raise ReleaseError("config blob exceeds its byte bound")
    if label != "config" and size > MAX_LAYER_COMPRESSED_BYTES:
        raise ReleaseError(f"{label} blob exceeds the compressed byte bound")
    if sha256_file(path) != descriptor["digest"]:
        raise ReleaseError(f"{label} blob digest differs from its descriptor")
    return path


@dataclass(frozen=True)
class VerifiedManifest:
    config: dict[str, Any]
    layers: list[dict[str, Any]]


def verify_manifest_envelope(
    root_raw: bytes,
    manifest_raw: bytes,
    expected_root_digest: str,
) -> VerifiedManifest:
    if DIGEST.fullmatch(expected_root_digest) is None:
        raise ReleaseError("expected registry digest is invalid")
    if sha256_bytes(root_raw) != expected_root_digest:
        raise ReleaseError("root manifest bytes differ from the registry digest")
    root = strict_json(root_raw, "root OCI manifest")
    if (
        not isinstance(root, dict)
        or type(root.get("schemaVersion")) is not int
        or root.get("schemaVersion") != 2
    ):
        raise ReleaseError("root OCI object is not schemaVersion 2")
    if root.get("mediaType") != OCI_MANIFEST or root_raw != manifest_raw:
        raise ReleaseError("registry root must be one direct OCI image manifest")

    manifest = strict_json(manifest_raw, "OCI image manifest")
    image = exact_keys(
        manifest, ["schemaVersion", "mediaType", "config", "layers"], "OCI image manifest"
    )
    if (
        type(image["schemaVersion"]) is not int
        or image["schemaVersion"] != 2
        or image["mediaType"] != OCI_MANIFEST
    ):
        raise ReleaseError("child object is not an OCI image manifest")
    config = _descriptor(image["config"], "config descriptor")
    if config["mediaType"] != OCI_CONFIG:
        raise ReleaseError("config descriptor media type is not OCI config")
    if config["size"] > MAX_CONFIG_BYTES:
        raise ReleaseError("config descriptor exceeds its byte bound")
    if (
        not isinstance(image["layers"], list)
        or not image["layers"]
        or len(image["layers"]) > MAX_LAYERS
    ):
        raise ReleaseError("OCI image has no filesystem layer")
    layers = []
    compressed_total = config["size"]
    for index, value in enumerate(image["layers"]):
        layer = _descriptor(value, f"layer {index} descriptor")
        if layer["mediaType"] != OCI_LAYER_GZIP:
            raise ReleaseError("every layer must be an OCI gzip filesystem layer")
        if layer["size"] > MAX_LAYER_COMPRESSED_BYTES:
            raise ReleaseError(f"layer {index} descriptor exceeds its byte bound")
        compressed_total += layer["size"]
        if compressed_total > MAX_IMAGE_COMPRESSED_BYTES:
            raise ReleaseError("OCI image exceeds the compressed byte bound")
        layers.append(layer)
    return VerifiedManifest(config=config, layers=layers)


def _validate_config(
    raw: bytes,
    manifest: VerifiedManifest,
    *,
    kind: str,
    source: str,
    release_id: str | None,
) -> list[str]:
    config = strict_json(raw, "OCI config", MAX_CONFIG_BYTES)
    value = exact_keys(
        config,
        ["architecture", "config", "created", "history", "os", "rootfs"],
        "OCI config",
    )
    if value["architecture"] != "amd64" or value["os"] != "linux":
        raise ReleaseError("OCI config platform is not exactly linux/amd64")
    rootfs = exact_keys(value["rootfs"], ["diff_ids", "type"], "OCI rootfs")
    if rootfs["type"] != "layers" or not isinstance(rootfs["diff_ids"], list):
        raise ReleaseError("OCI config rootfs is invalid")
    diff_ids = rootfs["diff_ids"]
    if len(diff_ids) != len(manifest.layers) or any(
        not isinstance(item, str) or DIGEST.fullmatch(item) is None for item in diff_ids
    ):
        raise ReleaseError("OCI config diff_ids do not exactly cover the layers")
    if not isinstance(value["created"], str) or not value["created"]:
        raise ReleaseError("OCI config has no creation timestamp")
    if not isinstance(value["history"], list):
        raise ReleaseError("OCI config history is not an array")
    nonempty_history = 0
    for entry in value["history"]:
        if not isinstance(entry, dict) or not set(entry).issubset(
            {"comment", "created", "created_by", "empty_layer"}
        ):
            raise ReleaseError("OCI config history contains an unknown shape")
        if entry.get("empty_layer") is not True:
            nonempty_history += 1
    if nonempty_history != len(manifest.layers):
        raise ReleaseError("OCI config history does not match filesystem layer count")

    runtime = value["config"]
    if kind == "files":
        expected_labels = {
            "io.opensteer.portablefs.release-record": f"/{FILES_RECORD_PATH}",
            "org.opencontainers.image.revision": source,
            "org.opencontainers.image.source": REPOSITORY_URL,
            "org.opencontainers.image.version": source,
        }
        expected_runtime = {
            "Entrypoint": [
                "/usr/bin/tini",
                "--",
                "/usr/local/bin/portablefs-files",
            ],
            "Env": [
                "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                "DEBIAN_FRONTEND=noninteractive",
            ],
            "ExposedPorts": {"4315/tcp": {}},
            "Labels": expected_labels,
            "User": "200102:200102",
            "WorkingDir": "/",
        }
    else:
        if release_id is None:
            raise ReleaseError("release capsule verification requires a release ID")
        expected_runtime = {
            "Env": ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],
            "Labels": {
                "io.opensteer.portablefs.release-record": CAPSULE_RECORD_CONTAINER_PATH,
                "org.opencontainers.image.revision": source,
                "org.opencontainers.image.source": REPOSITORY_URL,
                "org.opencontainers.image.version": release_id,
            },
            "WorkingDir": "/",
        }
    if runtime != expected_runtime:
        raise ReleaseError(f"{kind} OCI runtime config is not exact")
    return diff_ids


def _overlay_files_layers(
    layers: list[list[tuple[str, LayerEntry]]], expected_source: str
) -> None:
    selected: dict[str, LayerEntry] = {}
    watched = {
        "bin",
        "etc",
        "etc/ssl",
        "etc/ssl/certs",
        "etc/ssl/certs/ca-certificates.crt",
        FILES_RECORD_PATH,
        "request-trust",
        "usr",
        "usr/bin",
        "usr/bin/curl",
        "usr/bin/dash",
        "usr/bin/sh",
        "usr/bin/tini",
        "usr/local",
        "usr/local/bin",
        "usr/local/share",
        "usr/local/share/portablefs",
        "usr/local/bin/portablefs-files",
        "var",
        "var/lib",
        "var/lib/portablefs-files",
    }
    for layer in layers:
        for name, entry in layer:
            base = posixpath.basename(name)
            parent = posixpath.dirname(name)
            if base == ".wh..wh..opq":
                prefix = f"{parent}/" if parent else ""
                selected = {
                    path: value
                    for path, value in selected.items()
                    if not path.startswith(prefix)
                }
                continue
            if base.startswith(".wh."):
                target = posixpath.join(parent, base.removeprefix(".wh."))
                selected = {
                    path: value
                    for path, value in selected.items()
                    if path != target and not path.startswith(f"{target}/")
                }
                continue
            if name in watched:
                selected[name] = entry

    expected = {
        "bin": ("symlink", 0o777, 0, 0, "usr/bin"),
        "etc": ("directory", 0o755, 0, 0, None),
        "etc/ssl": ("directory", 0o755, 0, 0, None),
        "etc/ssl/certs": ("directory", 0o755, 0, 0, None),
        "etc/ssl/certs/ca-certificates.crt": ("file", 0o644, 0, 0, None),
        FILES_RECORD_PATH: ("file", 0o444, 0, 0, None),
        "request-trust": ("directory", 0o755, 0, 0, None),
        "usr": ("directory", 0o755, 0, 0, None),
        "usr/bin": ("directory", 0o755, 0, 0, None),
        "usr/bin/curl": ("file", 0o755, 0, 0, None),
        "usr/bin/dash": ("file", 0o755, 0, 0, None),
        "usr/bin/sh": ("symlink", 0o777, 0, 0, "dash"),
        "usr/bin/tini": ("file", 0o755, 0, 0, None),
        "usr/local": ("directory", 0o755, 0, 0, None),
        "usr/local/bin": ("directory", 0o755, 0, 0, None),
        "usr/local/bin/portablefs-files": ("file", 0o555, 0, 0, None),
        "usr/local/share": ("directory", 0o755, 0, 0, None),
        "usr/local/share/portablefs": ("directory", 0o755, 0, 0, None),
        "var": ("directory", 0o755, 0, 0, None),
        "var/lib": ("directory", 0o755, 0, 0, None),
        "var/lib/portablefs-files": (
            "directory",
            0o700,
            200102,
            200102,
            None,
        ),
    }
    if set(selected) != set(expected):
        raise ReleaseError("portablefs-files rootfs is missing a required exact member")
    for name, wanted in expected.items():
        entry = selected[name]
        if (entry.kind, entry.mode, entry.uid, entry.gid, entry.linkname) != wanted:
            raise ReleaseError(f"portablefs-files rootfs member is unsafe: {name}")
    for name in (
        "etc/ssl/certs/ca-certificates.crt",
        "usr/bin/curl",
        "usr/bin/dash",
        "usr/bin/tini",
        "usr/local/bin/portablefs-files",
    ):
        if selected[name].size == 0:
            raise ReleaseError(f"portablefs-files rootfs member is empty: {name}")
    record = selected[FILES_RECORD_PATH].data
    if record is None:
        raise ReleaseError("portablefs-files release record bytes were not captured")
    validate_files_record(record, expected_source)
    binary = selected["usr/local/bin/portablefs-files"]
    if binary.data is None or binary.size == 0 or not binary.data.startswith(b"\x7fELF"):
        raise ReleaseError("portablefs-files binary is not a nonempty ELF file")


def _verify_capsule_layer(
    entries: list[tuple[str, LayerEntry]],
    *,
    source: str,
    files_image: str | None,
    source_root: Path | None,
) -> dict[str, Any]:
    actual: dict[str, LayerEntry] = {}
    for name, entry in entries:
        if name.startswith(".wh.") or "/.wh." in name:
            raise ReleaseError("release capsule may not contain whiteouts")
        actual[name] = entry
    expected_paths = set(CAPSULE_DIRECTORIES) | set(CAPSULE_FILE_MODES)
    if set(actual) != expected_paths:
        raise ReleaseError("release capsule layer membership is not exact")
    total = 0
    for directory in CAPSULE_DIRECTORIES:
        entry = actual[directory]
        if (entry.kind, entry.mode, entry.uid, entry.gid) != (
            "directory",
            0o755,
            0,
            0,
        ):
            raise ReleaseError(f"release capsule directory is unsafe: {directory}")
    for path, mode in CAPSULE_FILE_MODES.items():
        entry = actual[path]
        if (entry.kind, entry.mode, entry.uid, entry.gid) != ("file", mode, 0, 0):
            raise ReleaseError(f"release capsule member is unsafe: {path}")
        if entry.data is None:
            raise ReleaseError(f"release capsule member was not captured: {path}")
        total += entry.size
    if total > MAX_CAPSULE_BYTES:
        raise ReleaseError("release capsule files exceed the total byte bound")
    record = validate_release_record(
        actual[CAPSULE_RECORD_PATH].data or b"",
        expected_source=source,
        expected_files_image=files_image,
    )
    release = record["release"]
    hosted_prefix = f"{CAPSULE_PREFIX}/hosted/"
    if actual[f"{hosted_prefix}source-commit"].data != f"{source}\n".encode():
        raise ReleaseError("capsule hosted source-commit differs from release.json")
    if actual[f"{hosted_prefix}release-id"].data != f"{release['releaseId']}\n".encode():
        raise ReleaseError("capsule hosted release-id differs from release.json")
    if actual[f"{hosted_prefix}architecture"].data != b"amd64\n":
        raise ReleaseError("capsule hosted architecture is not amd64")
    client = actual[f"{hosted_prefix}bin/portablefs"].data or b""
    if sha256_bytes(client) != release["clientSha256"]:
        raise ReleaseError("capsule client digest differs from release.json")

    checksum_raw = actual[f"{hosted_prefix}SHA256SUMS"].data or b""
    try:
        checksum_lines = checksum_raw.decode("ascii").splitlines()
    except UnicodeDecodeError as error:
        raise ReleaseError("capsule SHA256SUMS is not ASCII") from error
    expected_checksum_members = sorted(
        relative for relative in HOSTED_MODES if relative != "SHA256SUMS"
    )
    if len(checksum_lines) != len(expected_checksum_members):
        raise ReleaseError("capsule SHA256SUMS count is not exact")
    for expected_name, line in zip(expected_checksum_members, checksum_lines, strict=True):
        match = re.fullmatch(r"([0-9a-f]{64})  ([^\x00\r\n]+)", line)
        if match is None or match.group(2) != expected_name:
            raise ReleaseError("capsule SHA256SUMS membership is not exact")
        member = actual[f"{hosted_prefix}{expected_name}"].data
        if member is None or hashlib.sha256(member).hexdigest() != match.group(1):
            raise ReleaseError(f"capsule SHA256SUMS mismatch for {expected_name}")

    if source_root is not None:
        for source_relative, destination_relative in HELPERS.items():
            source_path = source_root / source_relative
            if not source_path.is_file() or source_path.is_symlink():
                raise ReleaseError(f"source helper is missing or unsafe: {source_relative}")
            embedded = actual[f"{CAPSULE_PREFIX}/{destination_relative}"].data
            if embedded != source_path.read_bytes():
                raise ReleaseError(f"capsule helper differs from source: {source_relative}")
    return record


def verify_remote_image(
    *,
    kind: str,
    source: str,
    expected_digest: str,
    root_manifest: Path,
    manifest_path: Path,
    blobs: Path,
    files_image: str | None = None,
    source_root: Path | None = None,
) -> dict[str, Any] | None:
    if kind not in {"files", "release"}:
        raise ReleaseError("image kind must be files or release")
    if not COMMIT.fullmatch(source) or source == "0" * 40:
        raise ReleaseError("expected source revision is invalid")
    root_raw = bounded_read(root_manifest, MAX_JSON_BYTES, "root OCI manifest")
    manifest_raw = bounded_read(manifest_path, MAX_JSON_BYTES, "OCI image manifest")
    envelope = verify_manifest_envelope(root_raw, manifest_raw, expected_digest)
    config_path = _verify_blob(blobs, envelope.config, "config")
    config_raw = bounded_read(config_path, MAX_CONFIG_BYTES, "OCI config")

    provisional_release_id = None
    if kind == "release":
        if files_image is not None and FILES_IMAGE.fullmatch(files_image) is None:
            raise ReleaseError("expected files image is not one exact digest reference")
        # The record is in the sole layer; its release ID is needed for the
        # exact config label and is cross-checked after layer validation.
        if len(envelope.layers) != 1:
            raise ReleaseError("release capsule must contain exactly one filesystem layer")
    diff_ids_value = strict_json(config_raw, "OCI config", MAX_CONFIG_BYTES)
    release_id_from_label = None
    if kind == "release" and isinstance(diff_ids_value, dict):
        runtime = diff_ids_value.get("config")
        if isinstance(runtime, dict) and isinstance(runtime.get("Labels"), dict):
            release_id_from_label = runtime["Labels"].get(
                "org.opencontainers.image.version"
            )
    if kind == "release" and not isinstance(release_id_from_label, str):
        raise ReleaseError("release OCI config has no release ID label")
    provisional_release_id = release_id_from_label
    diff_ids = _validate_config(
        config_raw,
        envelope,
        kind=kind,
        source=source,
        release_id=provisional_release_id,
    )

    decoded_layers: list[list[tuple[str, LayerEntry]]] = []
    uncompressed_total = 0
    for index, (descriptor, diff_id) in enumerate(
        zip(envelope.layers, diff_ids, strict=True)
    ):
        blob = _verify_blob(blobs, descriptor, f"layer {index}")
        entries, uncompressed_size = _read_layer(
            blob, diff_id, capture_all=kind == "release"
        )
        uncompressed_total += uncompressed_size
        if uncompressed_total > MAX_IMAGE_UNCOMPRESSED_BYTES:
            raise ReleaseError("OCI image exceeds the uncompressed byte bound")
        decoded_layers.append(entries)

    if kind == "files":
        _overlay_files_layers(decoded_layers, source)
        return None
    record = _verify_capsule_layer(
        decoded_layers[0],
        source=source,
        files_image=files_image,
        source_root=source_root,
    )
    if record["release"]["releaseId"] != provisional_release_id:
        raise ReleaseError("release ID label differs from capsule release.json")
    return record


def list_blob_descriptors(manifest_path: Path) -> list[dict[str, Any]]:
    raw = bounded_read(manifest_path, MAX_JSON_BYTES, "OCI image manifest")
    manifest = strict_json(raw, "OCI image manifest")
    image = exact_keys(
        manifest, ["schemaVersion", "mediaType", "config", "layers"], "OCI image manifest"
    )
    if (
        type(image["schemaVersion"]) is not int
        or image["schemaVersion"] != 2
        or image["mediaType"] != OCI_MANIFEST
    ):
        raise ReleaseError("blob listing input is not an OCI image manifest")
    config = _descriptor(image["config"], "config descriptor")
    if config["mediaType"] != OCI_CONFIG:
        raise ReleaseError("blob listing config is not OCI config")
    if config["size"] > MAX_CONFIG_BYTES:
        raise ReleaseError("blob listing config exceeds its byte bound")
    result = [config]
    compressed_total = config["size"]
    if (
        not isinstance(image["layers"], list)
        or not image["layers"]
        or len(image["layers"]) > MAX_LAYERS
    ):
        raise ReleaseError("blob listing image has no layers")
    for index, value in enumerate(image["layers"]):
        descriptor = _descriptor(value, f"layer {index} descriptor")
        if descriptor["mediaType"] != OCI_LAYER_GZIP:
            raise ReleaseError("blob listing layer is not OCI gzip")
        if descriptor["size"] > MAX_LAYER_COMPRESSED_BYTES:
            raise ReleaseError("blob listing layer exceeds its byte bound")
        compressed_total += descriptor["size"]
        if compressed_total > MAX_IMAGE_COMPRESSED_BYTES:
            raise ReleaseError("blob listing image exceeds the compressed byte bound")
        result.append(descriptor)
    digests = [descriptor["digest"] for descriptor in result]
    if len(digests) != len(set(digests)):
        raise ReleaseError("OCI manifest repeats a blob digest")
    return result


def list_blob_digests(manifest_path: Path) -> list[str]:
    return [descriptor["digest"] for descriptor in list_blob_descriptors(manifest_path)]


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    assemble = commands.add_parser("assemble")
    assemble.add_argument("--hosted", type=Path, required=True)
    assemble.add_argument("--output", type=Path, required=True)
    assemble.add_argument("--source", required=True)
    assemble.add_argument("--release-id", required=True)
    assemble.add_argument("--files-image", required=True)

    verify = commands.add_parser("verify-directory")
    verify.add_argument("directory", type=Path)
    verify.add_argument("--source", required=True)
    verify.add_argument("--files-image", required=True)

    blobs = commands.add_parser("list-blob-descriptors")
    blobs.add_argument("manifest", type=Path)

    copy = commands.add_parser("bounded-copy")
    copy.add_argument("--output", type=Path, required=True)
    copy.add_argument("--maximum", type=int, required=True)
    copy.add_argument("--exact-size", type=int)

    remote = commands.add_parser("verify-remote")
    remote.add_argument("--kind", choices=["files", "release"], required=True)
    remote.add_argument("--source", required=True)
    remote.add_argument("--digest", required=True)
    remote.add_argument("--root-manifest", type=Path, required=True)
    remote.add_argument("--manifest", type=Path, required=True)
    remote.add_argument("--blobs", type=Path, required=True)
    remote.add_argument("--files-image")
    remote.add_argument("--source-root", type=Path)
    remote.add_argument("--emit-infra-record")
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    try:
        if args.command == "assemble":
            assemble_capsule(
                args.hosted,
                args.output,
                args.source,
                args.release_id,
                args.files_image,
            )
        elif args.command == "verify-directory":
            verify_capsule_directory(
                args.directory,
                expected_source=args.source,
                expected_files_image=args.files_image,
            )
        elif args.command == "list-blob-descriptors":
            for descriptor in list_blob_descriptors(args.manifest):
                print(f"{descriptor['digest']}\t{descriptor['size']}")
        elif args.command == "bounded-copy":
            bounded_stdin_copy(args.output, args.maximum, args.exact_size)
        else:
            record = verify_remote_image(
                kind=args.kind,
                source=args.source,
                expected_digest=args.digest,
                root_manifest=args.root_manifest,
                manifest_path=args.manifest,
                blobs=args.blobs,
                files_image=args.files_image,
                source_root=args.source_root,
            )
            if args.emit_infra_record is not None:
                if record is None:
                    raise ReleaseError("only a release capsule can emit an infra record")
                sys.stdout.buffer.write(
                    canonical_json(infra_release_record(record, args.emit_infra_record))
                )
            elif record is not None:
                print(record["release"]["releaseId"])
    except (
        OSError,
        ReleaseError,
        subprocess.CalledProcessError,
        subprocess.TimeoutExpired,
    ) as error:
        print(f"portablefs release registry: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
