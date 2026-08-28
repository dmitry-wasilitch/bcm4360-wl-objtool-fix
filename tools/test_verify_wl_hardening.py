#!/usr/bin/env python3

import argparse
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).parent))
import verify_wl_hardening as verifier


class VerifierSecurityTests(unittest.TestCase):
    def parse_relocations(self, lines: list[str], size: int) -> verifier.RelocationMap:
        noun = "entry" if len(lines) == 1 else "entries"
        output = "\n".join(
            [
                "Relocation section '.rela.return_sites' at offset 0x100 "
                f"contains {len(lines)} {noun}:",
                *lines,
            ]
        )
        return verifier.parse_relocations(output, pathlib.Path("test.ko"), size)

    def test_trusted_tool_is_not_selected_from_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fake = pathlib.Path(directory) / "readelf"
            fake.write_text("#!/bin/sh\nexit 99\n", encoding="utf-8")
            fake.chmod(0o755)
            with mock.patch.dict(os.environ, {"PATH": directory}):
                selected = verifier.trusted_tool("readelf")
                self.assertNotEqual(selected, fake)
                self.assertIn(
                    selected.parent.resolve(),
                    tuple(path.resolve() for path in verifier.SYSTEM_TOOL_DIRS),
                )

    def test_modinfo_keeps_multicall_command_name(self) -> None:
        selected = verifier.trusted_tool("modinfo")
        self.assertEqual(selected.name, "modinfo")

    def test_oversized_input_fails_before_tool_execution(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            oversized = pathlib.Path(directory) / "oversized.ko"
            with oversized.open("wb") as handle:
                handle.truncate(verifier.MAX_INPUT_SIZE + 1)
            args = argparse.Namespace(
                module=oversized,
                blob=oversized,
                glue=[oversized] * len(verifier.EXPECTED_GLUE_NAMES),
                kernel="test",
            )
            with mock.patch.object(verifier, "run") as run:
                with self.assertRaisesRegex(verifier.GateError, "input is larger"):
                    verifier.verify(args)
                run.assert_not_called()

    def test_modified_closed_prefix_is_rejected(self) -> None:
        module = pathlib.Path("module.ko")
        blob = pathlib.Path("wlc_hybrid.o_shipped")

        def sections(path: pathlib.Path, _section: str) -> bytes:
            return b"original-blob" if path == blob else b"changed--blobopen-glue"

        with mock.patch.object(verifier, "section_bytes", side_effect=sections):
            with self.assertRaisesRegex(verifier.GateError, "pinned closed .text prefix"):
                verifier.verify_embedded_blob(module, blob)

    def test_unchanged_closed_prefix_is_accepted(self) -> None:
        module = pathlib.Path("module.ko")
        blob = pathlib.Path("wlc_hybrid.o_shipped")

        def sections(path: pathlib.Path, _section: str) -> bytes:
            return b"original-blob" if path == blob else b"original-blobopen-glue"

        with mock.patch.object(verifier, "section_bytes", side_effect=sections):
            verifier.verify_embedded_blob(module, blob)

    def test_non_executable_text_section_is_rejected(self) -> None:
        section = verifier.SectionInfo(4, "PROGBITS", 0, 64, 128, "A")
        with mock.patch.object(verifier, "section_info", return_value=section):
            with self.assertRaisesRegex(verifier.GateError, "section semantics"):
                verifier.validate_executable_text(pathlib.Path("test.ko"))

    def test_boundary_symbol_must_match_text_section_and_offset(self) -> None:
        symbol_table = (
            " 42: 0000000000001000 16 FUNC GLOBAL DEFAULT 5 "
            "__pfx_osl_error\n"
        )
        with mock.patch.object(verifier, "run", return_value=symbol_table):
            with self.assertRaisesRegex(verifier.GateError, "boundary symbol"):
                verifier.require_boundary_symbol(
                    pathlib.Path("test.ko"), "__pfx_osl_error", 4, 0x1000
                )

    def test_tool_timeout_fails_closed(self) -> None:
        with mock.patch.object(
            subprocess,
            "Popen",
            side_effect=subprocess.TimeoutExpired("readelf", verifier.TOOL_TIMEOUT_SECONDS),
        ):
            with self.assertRaisesRegex(verifier.GateError, "exceeded"):
                verifier.run("readelf", "-SW", "/tmp/input")

    def test_tool_output_is_capped_while_process_is_running(self) -> None:
        with mock.patch.dict(
            verifier.TRUSTED_TOOLS, {"readelf": pathlib.Path("/usr/bin/yes")}
        ), mock.patch.object(verifier, "MAX_TOOL_OUTPUT", 1024):
            with self.assertRaisesRegex(verifier.GateError, "excessive output"):
                verifier.run("readelf", "ignored")

    def test_snapshot_rejects_symbolic_link(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            source = root / "source"
            source.write_bytes(b"input")
            link = root / "link"
            link.symlink_to(source)
            with self.assertRaisesRegex(verifier.GateError, "open input safely"):
                verifier.snapshot_input(link, root / "snapshot")

    def test_return_site_slots_are_contiguous_pc32_records(self) -> None:
        parsed = self.parse_relocations(
            [
                "0000000000000000  0000000100000002 R_X86_64_PC32 "
                "0000000000000000 .text + 10",
                "0000000000000004  0000000100000002 R_X86_64_PC32 "
                "0000000000000000 .text + 20",
            ],
            8,
        )
        self.assertEqual(parsed.return_slot_offsets, (0, 4))
        self.assertEqual(parsed.return_sites, {(".text", 0x10), (".text", 0x20)})

    def test_wrong_return_site_relocation_type_is_rejected(self) -> None:
        with self.assertRaisesRegex(verifier.GateError, "unexpected return-site"):
            self.parse_relocations(
                [
                    "0000000000000000  0000000100000001 R_X86_64_64 "
                    "0000000000000000 .text + 10"
                ],
                4,
            )

    def test_unparsed_return_site_relocation_is_rejected(self) -> None:
        with self.assertRaisesRegex(verifier.GateError, "cannot parse"):
            self.parse_relocations(
                [
                    "0000000000000000  0000000100000002 R_X86_64_PC32 "
                    "0000000000000000 .text"
                ],
                4,
            )

    def test_return_thunk_addend_must_be_minus_four(self) -> None:
        output = "\n".join(
            [
                "Relocation section '.rela.text' at offset 0x100 contains 1 entry:",
                "0000000000000002  0000000100000004 R_X86_64_PLT32 "
                "0000000000000000 __x86_return_thunk + 0",
            ]
        )
        with self.assertRaisesRegex(verifier.GateError, "addend 0, expected -4"):
            verifier.parse_relocations(output, pathlib.Path("test.ko"), 0)

    def test_defined_return_thunk_symbol_is_rejected(self) -> None:
        symbol_table = (
            "  42: 0000000000001000 0 NOTYPE GLOBAL DEFAULT 1 "
            "__x86_return_thunk\n"
        )
        with mock.patch.object(verifier, "run", return_value=symbol_table):
            with self.assertRaisesRegex(verifier.GateError, "undefined kernel symbol"):
                verifier.require_undefined_symbol(
                    pathlib.Path("test.ko"), "__x86_return_thunk"
                )

    def test_prefixed_raw_returns_are_detected_from_bytes(self) -> None:
        disassembly = "\n".join(
            [
                "Disassembly of section .text:",
                "   0: 66 c3                 retw",
                "   2: f3 c3                 repz ret",
                "   4: c2 08 00              ret $0x8",
            ]
        )
        with mock.patch.object(verifier, "run", return_value=disassembly):
            sites = verifier.decoded_return_sites(pathlib.Path("test.ko"))
        self.assertEqual(len(sites), 3)

    def test_unannotated_cs_jump_is_still_counted(self) -> None:
        disassembly = "\n".join(
            [
                "Disassembly of section .text:",
                "  10: 2e e9 00 00 00 00     cs jmp 16 <f+0x6>",
            ]
        )
        with mock.patch.object(verifier, "run", return_value=disassembly):
            sites = verifier.disassembled_thunk_sites(pathlib.Path("test.ko"))
        self.assertEqual(sites, {(".text", 0x10)})

    def test_pc_relative_metadata_slots_and_size_are_validated(self) -> None:
        output = "\n".join(
            [
                "Relocation section '.rela.retpoline_sites' at offset 0x100 "
                "contains 2 entries:",
                "0000000000000000  0000000100000002 R_X86_64_PC32 "
                "0000000000000000 .text + 10",
                "0000000000000004  0000000100000002 R_X86_64_PC32 "
                "0000000000000000 .text + 20",
            ]
        )
        with mock.patch.object(verifier, "section_file_range", return_value=(0, 8)):
            count = verifier.validate_pc_relative_metadata(
                pathlib.Path("test.ko"), output, ".retpoline_sites"
            )
        self.assertEqual(count, 2)

    def test_pc_relative_metadata_rejects_non_pc32_record(self) -> None:
        output = "\n".join(
            [
                "Relocation section '.rela.ibt_endbr_seal' at offset 0x100 "
                "contains 1 entry:",
                "0000000000000000  0000000100000001 R_X86_64_64 "
                "0000000000000000 .text + 10",
            ]
        )
        with self.assertRaisesRegex(verifier.GateError, "unexpected .* relocation"):
            verifier.validate_pc_relative_metadata(
                pathlib.Path("test.ko"), output, ".ibt_endbr_seal"
            )

    def test_duplicate_return_site_slot_is_rejected(self) -> None:
        with self.assertRaisesRegex(verifier.GateError, "duplicate .* slot"):
            self.parse_relocations(
                [
                    "0000000000000000  0000000100000002 R_X86_64_PC32 "
                    "0000000000000000 .text + 10",
                    "0000000000000000  0000000100000002 R_X86_64_PC32 "
                    "0000000000000000 .text + 20",
                ],
                8,
            )

    def test_return_site_slot_hole_is_rejected(self) -> None:
        with self.assertRaisesRegex(verifier.GateError, "slots have holes"):
            self.parse_relocations(
                [
                    "0000000000000000  0000000100000002 R_X86_64_PC32 "
                    "0000000000000000 .text + 10",
                    "0000000000000008  0000000100000002 R_X86_64_PC32 "
                    "0000000000000000 .text + 20",
                ],
                8,
            )

    def test_return_site_section_size_must_match_record_count(self) -> None:
        with self.assertRaisesRegex(verifier.GateError, "size does not match"):
            self.parse_relocations(
                [
                    "0000000000000000  0000000100000002 R_X86_64_PC32 "
                    "0000000000000000 .text + 10"
                ],
                8,
            )

    def test_duplicate_return_site_target_is_rejected(self) -> None:
        with self.assertRaisesRegex(verifier.GateError, "duplicate .* target"):
            self.parse_relocations(
                [
                    "0000000000000000  0000000100000002 R_X86_64_PC32 "
                    "0000000000000000 .text + 10",
                    "0000000000000004  0000000100000002 R_X86_64_PC32 "
                    "0000000000000000 .text + 10",
                ],
                8,
            )


if __name__ == "__main__":
    unittest.main()
