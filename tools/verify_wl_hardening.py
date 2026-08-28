#!/usr/bin/env python3
"""Static gate for the BCM4360 wl compatibility build.

This verifier intentionally makes no claim that Broadcom's closed
wlc_hybrid.o_shipped has modern return-thunk hardening.  It proves that every
compiler-generated return-thunk jump in the final module has objtool metadata,
and that all decoded raw returns come from the unchanged closed object.  When
the four build-tree glue objects are supplied, it checks them independently as
an additional provenance gate.
"""

from __future__ import annotations

import argparse
import contextvars
import dataclasses
import hashlib
import os
import pathlib
import re
import selectors
import stat
import subprocess
import sys
import tempfile
import time


EXPECTED_BLOB_SHA256 = (
    "352a6e349f74c69b78e76f68c63752c99b8f6b22dc942af531b754211d7f4743"
)
EXPECTED_GLUE_NAMES = {
    "linux_osl.o",
    "wl_cfg80211_hybrid.o",
    "wl_iw.o",
    "wl_linux.o",
}
SYSTEM_TOOL_DIRS = (pathlib.Path("/usr/bin"), pathlib.Path("/bin"))
TOOL_NAMES = ("file", "modinfo", "objdump", "readelf")
MAX_INPUT_SIZE = 16 * 1024 * 1024
MAX_TOOL_OUTPUT = 64 * 1024 * 1024
TOOL_TIMEOUT_SECONDS = 120
TOTAL_TIMEOUT_SECONDS = 300
IO_CHUNK_SIZE = 64 * 1024

VERIFICATION_DEADLINE: contextvars.ContextVar[float | None] = contextvars.ContextVar(
    "verification_deadline", default=None
)


class GateError(RuntimeError):
    pass


@dataclasses.dataclass(frozen=True)
class RelocationMap:
    return_sites: frozenset[tuple[str, int]]
    thunk_sites: frozenset[tuple[str, int]]
    return_slot_offsets: tuple[int, ...]


@dataclasses.dataclass(frozen=True)
class SectionInfo:
    index: int
    section_type: str
    address: int
    offset: int
    size: int
    flags: str


def trusted_tool(name: str) -> pathlib.Path:
    for directory in SYSTEM_TOOL_DIRS:
        candidate = directory / name
        try:
            resolved = candidate.resolve(strict=True)
            mode = resolved.stat()
        except FileNotFoundError:
            continue
        if not stat.S_ISREG(mode.st_mode) or not os.access(resolved, os.X_OK):
            continue
        if mode.st_uid != 0 or mode.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise GateError(f"unsafe system tool: {resolved}")
        # Keep the trusted symlink path as argv[0].  Multi-call binaries such
        # as kmod select their command mode from that name (for example
        # /usr/bin/modinfo -> kmod).
        return candidate
    raise GateError(f"missing trusted system tool: {name}")


TRUSTED_TOOLS: dict[str, pathlib.Path] = {}


def run(tool: str, *args: str) -> str:
    if tool not in TOOL_NAMES:
        raise GateError(f"unsupported system tool: {tool}")
    executable = TRUSTED_TOOLS.get(tool)
    if executable is None:
        executable = trusted_tool(tool)
        TRUSTED_TOOLS[tool] = executable
    environment = {"LANG": "C", "LC_ALL": "C"}
    now = time.monotonic()
    per_tool_deadline = now + TOOL_TIMEOUT_SECONDS
    verification_deadline = VERIFICATION_DEADLINE.get()
    deadline = (
        min(per_tool_deadline, verification_deadline)
        if verification_deadline is not None
        else per_tool_deadline
    )
    if deadline <= now:
        raise GateError(f"verification exceeded {TOTAL_TIMEOUT_SECONDS} seconds")

    try:
        proc = subprocess.Popen(
            [str(executable), *args],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
        )
    except subprocess.TimeoutExpired as exc:
        raise GateError(f"{tool} exceeded {TOOL_TIMEOUT_SECONDS} seconds") from exc
    except OSError as exc:
        raise GateError(f"cannot execute trusted system tool {tool}: {exc}") from exc

    assert proc.stdout is not None and proc.stderr is not None
    streams = {proc.stdout: bytearray(), proc.stderr: bytearray()}
    selector = selectors.DefaultSelector()
    selector.register(proc.stdout, selectors.EVENT_READ)
    selector.register(proc.stderr, selectors.EVENT_READ)
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired([str(executable), *args], 0)
            for key, _events in selector.select(min(remaining, 0.25)):
                chunk = os.read(key.fd, IO_CHUNK_SIZE)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                buffer = streams[key.fileobj]
                if len(buffer) + len(chunk) > MAX_TOOL_OUTPUT:
                    raise GateError(f"{tool} produced excessive output")
                buffer.extend(chunk)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise subprocess.TimeoutExpired([str(executable), *args], 0)
        proc.wait(timeout=remaining)
    except (GateError, subprocess.TimeoutExpired) as exc:
        proc.kill()
        proc.wait()
        if isinstance(exc, GateError):
            raise
        if verification_deadline is not None and deadline == verification_deadline:
            raise GateError(
                f"verification exceeded {TOTAL_TIMEOUT_SECONDS} seconds"
            ) from exc
        raise GateError(f"{tool} exceeded {TOOL_TIMEOUT_SECONDS} seconds") from exc
    finally:
        selector.close()
        proc.stdout.close()
        proc.stderr.close()

    output = streams[proc.stdout].decode("utf-8", errors="replace")
    error = streams[proc.stderr].decode("utf-8", errors="replace")

    if proc.returncode:
        detail = error.strip() or output.strip()
        raise GateError(f"{tool} {' '.join(args)} failed: {detail}")
    return output


def snapshot_input(source: pathlib.Path, destination: pathlib.Path) -> str:
    """Copy one stable regular-file view and return its SHA-256 digest."""
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(source, flags)
    except OSError as exc:
        raise GateError(f"cannot open input safely: {source}: {exc}") from exc

    digest = hashlib.sha256()
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise GateError(f"input is not a regular file: {source}")
        if before.st_size > MAX_INPUT_SIZE:
            raise GateError(f"input is larger than {MAX_INPUT_SIZE} bytes: {source}")
        copied = 0
        with os.fdopen(descriptor, "rb", closefd=False) as input_handle, destination.open(
            "xb"
        ) as output_handle:
            while True:
                chunk = input_handle.read(IO_CHUNK_SIZE)
                if not chunk:
                    break
                copied += len(chunk)
                if copied > MAX_INPUT_SIZE:
                    raise GateError(
                        f"input is larger than {MAX_INPUT_SIZE} bytes: {source}"
                    )
                output_handle.write(chunk)
                digest.update(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)

    stable_fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
    if copied != before.st_size or any(
        getattr(before, field) != getattr(after, field) for field in stable_fields
    ):
        raise GateError(f"input changed while it was snapshotted: {source}")
    destination.chmod(0o400)
    return digest.hexdigest()


def section_names(path: pathlib.Path) -> set[str]:
    output = run("readelf", "-SW", str(path))
    return set(re.findall(r"\[\s*\d+\]\s+(\S+)", output))


def section_info(path: pathlib.Path, section: str) -> SectionInfo:
    output = run("readelf", "-SW", str(path))
    match = re.search(
        rf"\[\s*(\d+)\]\s+{re.escape(section)}\s+(\S+)\s+"
        r"([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+"
        r"[0-9a-fA-F]+\s+(\S*)\s+\d+\s+\d+\s+\d+",
        output,
    )
    if not match:
        raise GateError(f"{path}: no {section} section")
    index, section_type, address, offset, size, flags = match.groups()
    return SectionInfo(
        int(index),
        section_type,
        int(address, 16),
        int(offset, 16),
        int(size, 16),
        flags,
    )


def section_file_range(path: pathlib.Path, section: str) -> tuple[int, int]:
    info = section_info(path, section)
    return info.offset, info.size


def validate_executable_text(path: pathlib.Path) -> SectionInfo:
    info = section_info(path, ".text")
    if (
        info.section_type != "PROGBITS"
        or info.address != 0
        or not {"A", "X"}.issubset(info.flags)
    ):
        raise GateError(f"{path}: unexpected .text section semantics")
    return info


def section_bytes(path: pathlib.Path, section: str) -> bytes:
    offset, size = section_file_range(path, section)
    if size > MAX_INPUT_SIZE:
        raise GateError(f"{path}: {section} section is too large")
    with path.open("rb") as handle:
        handle.seek(offset)
        data = handle.read(size)
    if len(data) != size:
        raise GateError(f"{path}: truncated {section} section")
    return data


def text_size(path: pathlib.Path) -> int:
    return section_file_range(path, ".text")[1]


def verify_embedded_blob(module: pathlib.Path, blob: pathlib.Path) -> None:
    blob_text = section_bytes(blob, ".text")
    module_text = section_bytes(module, ".text")
    if not module_text.startswith(blob_text):
        raise GateError("final module does not contain the pinned closed .text prefix")


def parse_relocations(
    output: str, path: pathlib.Path, return_sites_size: int
) -> RelocationMap:
    """Parse and validate x86-64 objtool return-site relocations."""
    current = ""
    return_site_records: list[tuple[str, int]] = []
    return_slot_offsets: list[int] = []
    thunk_sites: set[tuple[str, int]] = set()
    section_re = re.compile(
        r"Relocation section '([^']+)'.* contains (\d+) entr(?:y|ies):"
    )
    entry_re = re.compile(
        r"^\s*([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+(\S+)\s+"
        r"[0-9a-fA-F]+\s+(\S+)\s+([+-])\s+([0-9a-fA-F]+)"
    )
    entry_prefix_re = re.compile(r"^\s*[0-9a-fA-F]+\s+[0-9a-fA-F]+\s+")
    return_sites_expected: int | None = None
    return_sites_seen = 0

    for line in output.splitlines():
        section_match = section_re.search(line)
        if section_match:
            current = section_match.group(1)
            if current == ".rela.return_sites":
                return_sites_expected = int(section_match.group(2))
            continue
        entry = entry_re.match(line)
        if not entry:
            if current == ".rela.return_sites" and entry_prefix_re.match(line):
                raise GateError(
                    f"{path}: cannot parse .return_sites relocation: {line.strip()}"
                )
            continue
        offset_hex, _info_hex, relocation_type, symbol, sign, addend_hex = (
            entry.groups()
        )
        offset = int(offset_hex, 16)
        addend = int(addend_hex, 16) * (1 if sign == "+" else -1)

        if current == ".rela.return_sites":
            return_sites_seen += 1
            if relocation_type != "R_X86_64_PC32":
                raise GateError(
                    f"{path}: unexpected return-site relocation {relocation_type}"
                )
            if not symbol.startswith("."):
                raise GateError(f"{path}: unexpected return-site symbol {symbol}")
            return_slot_offsets.append(offset)
            return_site_records.append((symbol, addend))
        elif symbol == "__x86_return_thunk":
            if not current.startswith(".rela"):
                raise GateError(f"{path}: thunk relocation outside RELA section")
            if relocation_type != "R_X86_64_PLT32":
                raise GateError(
                    f"{path}: unexpected return-thunk relocation {relocation_type}"
                )
            if addend != -4:
                raise GateError(
                    f"{path}: return-thunk relocation has addend {addend}, expected -4"
                )
            if offset < 2:
                raise GateError(f"{path}: invalid return-thunk relocation offset")
            code_section = current[len(".rela") :]
            # This kernel uses the six-byte `cs jmp rel32` encoding.  The
            # relocation covers the four-byte displacement at instruction+2.
            thunk_sites.add((code_section, offset - 2))

    if return_sites_expected is None:
        if return_sites_size:
            raise GateError(f"{path}: missing .rela.return_sites table")
    elif return_sites_seen != return_sites_expected:
        raise GateError(
            f"{path}: parsed {return_sites_seen} of {return_sites_expected} "
            ".return_sites relocations"
        )

    return_sites = frozenset(return_site_records)
    slots = tuple(return_slot_offsets)
    if len(set(slots)) != len(slots):
        raise GateError(f"{path}: duplicate .return_sites relocation slot")
    expected_slots = set(range(0, 4 * len(slots), 4))
    if set(slots) != expected_slots:
        raise GateError(f"{path}: .return_sites relocation slots have holes")
    if return_sites_size != 4 * len(slots):
        raise GateError(
            f"{path}: .return_sites size does not match relocation count"
        )
    if len(return_sites) != len(return_site_records):
        raise GateError(f"{path}: duplicate .return_sites target")

    return RelocationMap(return_sites, frozenset(thunk_sites), slots)


def relocations(path: pathlib.Path) -> RelocationMap:
    output = run("readelf", "-Wr", str(path))
    names = section_names(path)
    has_sites = ".return_sites" in names
    has_relocations = ".rela.return_sites" in names
    if has_sites != has_relocations:
        raise GateError(f"{path}: incomplete return-site section pair")
    return_sites_size = section_file_range(path, ".return_sites")[1] if has_sites else 0
    return parse_relocations(output, path, return_sites_size)


def validate_pc_relative_metadata(
    path: pathlib.Path, output: str, section: str
) -> int:
    """Validate one objtool metadata array and its RELA table structurally."""
    relocation_section = f".rela{section}"
    current = ""
    expected: int | None = None
    offsets: list[int] = []
    section_re = re.compile(
        r"Relocation section '([^']+)'.* contains (\d+) entr(?:y|ies):"
    )
    entry_re = re.compile(
        r"^\s*([0-9a-fA-F]+)\s+[0-9a-fA-F]+\s+(\S+)\s+"
        r"[0-9a-fA-F]+\s+\S+\s+[+-]\s+[0-9a-fA-F]+"
    )
    entry_prefix_re = re.compile(r"^\s*[0-9a-fA-F]+\s+[0-9a-fA-F]+\s+")

    for line in output.splitlines():
        section_match = section_re.search(line)
        if section_match:
            current = section_match.group(1)
            if current == relocation_section:
                expected = int(section_match.group(2))
            continue
        if current != relocation_section:
            continue
        entry = entry_re.match(line)
        if not entry:
            if entry_prefix_re.match(line):
                raise GateError(
                    f"{path}: cannot parse {section} relocation: {line.strip()}"
                )
            continue
        offset_hex, relocation_type = entry.groups()
        if relocation_type != "R_X86_64_PC32":
            raise GateError(
                f"{path}: unexpected {section} relocation {relocation_type}"
            )
        offsets.append(int(offset_hex, 16))

    if expected is None:
        raise GateError(f"{path}: missing {relocation_section} table")
    if len(offsets) != expected:
        raise GateError(
            f"{path}: parsed {len(offsets)} of {expected} {section} relocations"
        )

    data_size = section_file_range(path, section)[1]
    if not data_size or data_size % 4:
        raise GateError(f"{path}: invalid {section} size {data_size}")
    if expected != data_size // 4:
        raise GateError(
            f"{path}: {section} size does not match relocation count"
        )
    if offsets != list(range(0, data_size, 4)):
        raise GateError(f"{path}: {section} relocation slots are not contiguous")
    return expected


def validate_objtool_metadata(path: pathlib.Path) -> None:
    """Check the record layout of non-return objtool metadata sections."""
    output = run("readelf", "-Wr", str(path))
    validate_pc_relative_metadata(path, output, ".retpoline_sites")
    validate_pc_relative_metadata(path, output, ".ibt_endbr_seal")
    orc_records = validate_pc_relative_metadata(path, output, ".orc_unwind_ip")
    orc_size = section_file_range(path, ".orc_unwind")[1]
    if orc_size != 6 * orc_records:
        raise GateError(
            f"{path}: .orc_unwind size does not match .orc_unwind_ip records"
        )


def disassembled_thunk_sites(path: pathlib.Path) -> set[tuple[str, int]]:
    output = run("objdump", "-dr", str(path))
    current = ""
    last_site: tuple[str, int] | None = None
    last_is_prefixed_jump = False
    result: set[tuple[str, int]] = set()
    section_re = re.compile(r"^Disassembly of section (\S+):$")
    insn_re = re.compile(
        r"^\s*([0-9a-fA-F]+):\s+((?:[0-9a-fA-F]{2}\s+)+)\s*(.*)$"
    )

    for line in output.splitlines():
        section_match = section_re.match(line)
        if section_match:
            current = section_match.group(1)
            last_site = None
            continue
        instruction = insn_re.match(line)
        if instruction:
            address_hex, byte_text, mnemonic = instruction.groups()
            encoded = bytes.fromhex(byte_text)
            last_site = (current, int(address_hex, 16))
            last_is_prefixed_jump = encoded == b"\x2e\xe9\x00\x00\x00\x00" and (
                "jmp" in mnemonic
            )
            if last_is_prefixed_jump:
                result.add(last_site)
            continue
        if "__x86_return_thunk" in line:
            if last_site is None or not last_is_prefixed_jump:
                raise GateError(
                    f"{path}: thunk relocation is not attached to `cs jmp rel32`: {line.strip()}"
                )

    return result


def decoded_return_sites(path: pathlib.Path) -> set[tuple[str, int, bytes]]:
    output = run("objdump", "-d", str(path))
    current = ""
    result: set[tuple[str, int, bytes]] = set()
    section_re = re.compile(r"^Disassembly of section (\S+):$")
    insn_re = re.compile(
        r"^\s*([0-9a-fA-F]+):\s+((?:[0-9a-fA-F]{2}\s+)+)\s*(.*)$"
    )
    legacy_prefixes = {
        0xF0,
        0xF2,
        0xF3,
        0x2E,
        0x36,
        0x3E,
        0x26,
        0x64,
        0x65,
        0x66,
        0x67,
    }

    for line in output.splitlines():
        section_match = section_re.match(line)
        if section_match:
            current = section_match.group(1)
            continue
        instruction = insn_re.match(line)
        if not instruction:
            continue
        address_hex, byte_text, mnemonic = instruction.groups()
        encoded = bytes.fromhex(byte_text)
        # Objdump wraps long instruction byte sequences onto continuation
        # lines with no mnemonic.  A trailing C3 byte on such a line is data
        # belonging to the preceding instruction, not a decoded return.
        if not mnemonic.strip():
            continue
        opcode_index = 0
        while opcode_index < len(encoded) and (
            encoded[opcode_index] in legacy_prefixes
            or 0x40 <= encoded[opcode_index] <= 0x4F
        ):
            opcode_index += 1
        remaining = encoded[opcode_index:]
        if remaining in (b"\xc3", b"\xcb") or (
            len(remaining) == 3 and remaining[0] in (0xC2, 0xCA)
        ):
            result.add((current, int(address_hex, 16), encoded))
    return result


def require_undefined_symbol(path: pathlib.Path, name: str) -> None:
    output = run("readelf", "-Ws", str(path))
    matches: list[list[str]] = []
    for line in output.splitlines():
        fields = line.split()
        if len(fields) >= 8 and fields[-1] == name and fields[0].endswith(":"):
            matches.append(fields)
    if not matches:
        raise GateError(f"{path}: missing symbol {name}")
    if any(fields[-2] != "UND" for fields in matches):
        raise GateError(f"{path}: {name} must be an undefined kernel symbol")


def require_boundary_symbol(
    path: pathlib.Path, name: str, text_index: int, expected_value: int
) -> None:
    output = run("readelf", "-Ws", str(path))
    matches: list[list[str]] = []
    for line in output.splitlines():
        fields = line.split()
        if len(fields) >= 8 and fields[-1] == name and fields[0].endswith(":"):
            matches.append(fields)
    if len(matches) != 1:
        raise GateError(f"{path}: expected exactly one {name} symbol")
    fields = matches[0]
    if (
        fields[3] != "FUNC"
        or fields[4] != "GLOBAL"
        or fields[5] != "DEFAULT"
        or not fields[6].isdigit()
        or int(fields[6]) != text_index
        or int(fields[1], 16) != expected_value
    ):
        raise GateError(f"{path}: invalid closed/open boundary symbol {name}")


def verify(args: argparse.Namespace) -> None:
    try:
        module_source = args.module.resolve(strict=True)
        blob_source = args.blob.resolve(strict=True)
        glue_sources = [path.resolve(strict=True) for path in args.glue]
    except FileNotFoundError as exc:
        raise GateError(f"missing input: {exc.filename}") from exc

    for path in [module_source, blob_source, *glue_sources]:
        try:
            status = path.stat()
        except OSError as exc:
            raise GateError(f"cannot stat input: {path}: {exc}") from exc
        if not stat.S_ISREG(status.st_mode):
            raise GateError(f"input is not a regular file: {path}")
        if status.st_size > MAX_INPUT_SIZE:
            raise GateError(f"input is larger than {MAX_INPUT_SIZE} bytes: {path}")

    glue_names = [path.name for path in glue_sources]
    if glue_names and (
        len(glue_names) != len(EXPECTED_GLUE_NAMES)
        or set(glue_names) != EXPECTED_GLUE_NAMES
    ):
        raise GateError(
            "expected exactly these glue objects: "
            + ", ".join(sorted(EXPECTED_GLUE_NAMES))
        )

    deadline_token = VERIFICATION_DEADLINE.set(
        time.monotonic() + TOTAL_TIMEOUT_SECONDS
    )
    try:
        with tempfile.TemporaryDirectory(prefix="wl-hardening-snapshot.") as directory:
            snapshot_root = pathlib.Path(directory)
            module_dir = snapshot_root / "module"
            blob_dir = snapshot_root / "blob"
            glue_dir = snapshot_root / "glue"
            module_dir.mkdir()
            blob_dir.mkdir()
            glue_dir.mkdir()

            module = module_dir / module_source.name
            blob = blob_dir / blob_source.name
            glue = [glue_dir / path.name for path in glue_sources]
            snapshot_input(module_source, module)
            blob_hash = snapshot_input(blob_source, blob)
            for source, destination in zip(glue_sources, glue, strict=True):
                snapshot_input(source, destination)
            _verify_snapshots(args, module, blob, glue, blob_hash)
    finally:
        VERIFICATION_DEADLINE.reset(deadline_token)


def _verify_snapshots(
    args: argparse.Namespace,
    module: pathlib.Path,
    blob: pathlib.Path,
    glue: list[pathlib.Path],
    blob_hash: str,
) -> None:
    if blob_hash != EXPECTED_BLOB_SHA256:
        raise GateError(f"closed blob hash mismatch: {blob_hash}")

    for path in (module, blob):
        file_description = run("file", str(path))
        if "ELF 64-bit LSB relocatable, x86-64" not in file_description:
            raise GateError(
                f"unexpected object format for {path}: {file_description.strip()}"
            )
    module_text = validate_executable_text(module)
    blob_text = validate_executable_text(blob)
    if module_text.size <= blob_text.size:
        raise GateError("final module has no open-code region after the closed blob")

    vermagic = run("modinfo", "-F", "vermagic", str(module)).split()
    if not vermagic or vermagic[0] != args.kernel:
        raise GateError(f"vermagic mismatch: {' '.join(vermagic)}")
    if run("modinfo", "-F", "license", str(module)).strip() != "MIXED/Proprietary":
        raise GateError("unexpected module license")
    if not args.unsigned_build_tree:
        if run("modinfo", "-F", "sig_id", str(module)).strip() != "PKCS#7":
            raise GateError("module has no PKCS#7 signature")
        if not run("modinfo", "-F", "signer", str(module)).strip():
            raise GateError("module signer is empty")

    required = {
        ".return_sites",
        ".rela.return_sites",
        ".orc_unwind",
        ".orc_unwind_ip",
        ".rela.orc_unwind_ip",
        ".retpoline_sites",
        ".rela.retpoline_sites",
        ".ibt_endbr_seal",
        ".rela.ibt_endbr_seal",
    }
    missing = required - section_names(module)
    if missing:
        raise GateError(f"missing objtool sections: {', '.join(sorted(missing))}")

    validate_objtool_metadata(module)
    require_undefined_symbol(module, "__x86_return_thunk")
    module_relocations = relocations(module)
    return_sites = module_relocations.return_sites
    thunk_sites = module_relocations.thunk_sites
    if not return_sites:
        raise GateError("module has no return-site metadata")
    if return_sites != thunk_sites:
        missing_metadata = thunk_sites - return_sites
        stale_metadata = return_sites - thunk_sites
        raise GateError(
            "return-site mismatch: "
            f"missing={sorted(missing_metadata)[:5]} "
            f"stale={sorted(stale_metadata)[:5]}"
        )

    decoded_sites = disassembled_thunk_sites(module)
    if decoded_sites != thunk_sites:
        raise GateError("readelf relocation map and objdump instruction map disagree")

    for path in glue:
        glue_names = section_names(path)
        if section_file_range(path, ".text")[1]:
            required_glue_metadata = {
                ".return_sites",
                ".rela.return_sites",
                ".orc_unwind",
                ".orc_unwind_ip",
                ".rela.orc_unwind_ip",
                ".retpoline_sites",
                ".rela.retpoline_sites",
                ".ibt_endbr_seal",
                ".rela.ibt_endbr_seal",
            }
            missing_glue_metadata = required_glue_metadata - glue_names
            if missing_glue_metadata:
                raise GateError(
                    f"{path}: missing objtool sections: "
                    + ", ".join(sorted(missing_glue_metadata))
                )
            validate_objtool_metadata(path)
        glue_relocations = relocations(path)
        if glue_relocations.return_sites != glue_relocations.thunk_sites:
            raise GateError(f"{path}: glue return-site mismatch")
        if decoded_return_sites(path):
            raise GateError(f"{path}: open glue contains raw returns")

    blob_return_sites = decoded_return_sites(blob)
    module_return_sites = decoded_return_sites(module)
    blob_returns = len(blob_return_sites)
    if not blob_returns or module_return_sites != blob_return_sites:
        raise GateError(
            "raw-return boundary mismatch: "
            f"blob={blob_returns} module={len(module_return_sites)}"
        )

    require_boundary_symbol(
        module, "__pfx_osl_error", module_text.index, blob_text.size
    )
    verify_embedded_blob(module, blob)

    print("PASS: BCM4360 wl static hardening gate")
    print(f"  kernel/vermagic: {args.kernel}")
    print(f"  closed blob SHA-256: {blob_hash}")
    print(f"  covered open-glue return thunks: {len(thunk_sites)}")
    print(f"  raw returns in open glue: 0")
    print(f"  raw returns confined to closed blob: {blob_returns}")
    if args.unsigned_build_tree:
        print("  signature metadata: skipped for unsigned same-tree build")
    else:
        print("  signature metadata: PKCS#7 fields present")
    print("  security boundary: closed .text prefix is unchanged, not modern-hardened")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("module", type=pathlib.Path)
    parser.add_argument("blob", type=pathlib.Path)
    parser.add_argument("--kernel", required=True)
    parser.add_argument("--glue", type=pathlib.Path, action="append", default=[])
    parser.add_argument(
        "--unsigned-build-tree",
        action="store_true",
        help="skip signature metadata for a module and glue from one local build tree",
    )
    args = parser.parse_args()
    try:
        verify(args)
    except GateError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
