import gzip
from pathlib import Path
import shutil
import subprocess

import pytest

from tests.trace_builder import (
    etrace_arch,
    etrace_exec64,
    qemu_simple_event,
    qemu_simple_header,
    qemu_simple_mapping,
)


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / ".test-build" / "coverage-fixture"


def symbol_address(name):
    result = subprocess.run(
        ["nm", "-S", str(FIXTURE)],
        text=True,
        capture_output=True,
        check=True,
    )
    for line in result.stdout.splitlines():
        fields = line.split(maxsplit=3)
        if len(fields) == 4 and fields[3] == name:
            return int(fields[0], 16)
    raise AssertionError(f"symbol {name!r} not found")


def run_lcov(run_etrace, tmp_path, trace, trace_format, *extra_args):
    output = tmp_path / f"{trace.stem}.info"
    result = run_etrace(
        "--trace",
        trace,
        "--trace-in-format",
        trace_format,
        "--trace-output",
        "none",
        "--elf",
        FIXTURE,
        "--dwarfdump",
        shutil.which("dwarfdump"),
        "--coverage-format",
        "lcov",
        "--coverage-output",
        output,
        *extra_args,
    )
    assert result.returncode == 0
    return output.read_text(encoding="utf-8")


def test_ascii_runtime_address_matches_linked_coverage(run_etrace, tmp_path):
    if shutil.which("dwarfdump") is None:
        pytest.skip("dwarfdump is required for LCOV generation")

    linked = symbol_address("covered")
    runtime = 0x10000000
    linked_trace = tmp_path / "linked.hex"
    runtime_trace = tmp_path / "runtime.hex"
    linked_trace.write_text(f"{linked:x}\n", encoding="ascii")
    runtime_trace.write_text(f"{runtime:x}\n", encoding="ascii")

    expected = run_lcov(run_etrace, tmp_path, linked_trace, "ascii-hex")
    actual = run_lcov(
        run_etrace,
        tmp_path,
        runtime_trace,
        "ascii-hex",
        "--address-map",
        f"{runtime:x}:{linked:x}:4",
    )

    assert actual == expected


def test_qemu_simple_runtime_address_is_normalized(run_etrace, tmp_path):
    if shutil.which("dwarfdump") is None:
        pytest.skip("dwarfdump is required for LCOV generation")

    linked = symbol_address("covered")
    runtime = 0x20000000
    trace = tmp_path / "runtime.simple"
    trace.write_bytes(
        qemu_simple_header()
        + qemu_simple_mapping(1, "tb_enter_exec")
        + qemu_simple_event(1, 0, runtime, runtime + 4)
    )

    output = run_lcov(
        run_etrace,
        tmp_path,
        trace,
        "qemu-simple",
        "--address-map",
        f"{runtime:x}:{linked:x}:4",
    )

    assert "FNDA:1,covered" in output


def test_gzip_etrace_runtime_address_is_normalized(run_etrace, tmp_path):
    if shutil.which("dwarfdump") is None:
        pytest.skip("dwarfdump is required for LCOV generation")

    linked = symbol_address("covered")
    runtime = 0x30000000
    trace = tmp_path / "runtime.etrace.gz"
    trace.write_bytes(
        gzip.compress(
            etrace_arch(guest_bits=64)
            + etrace_exec64(duration=0, start=runtime, end=runtime + 4)
        )
    )

    output = run_lcov(
        run_etrace,
        tmp_path,
        trace,
        "etrace",
        "--address-map",
        f"{runtime:x}:{linked:x}:4",
    )

    assert "FNDA:1,covered" in output


def test_etrace_display_splits_mapping_boundary(run_etrace, tmp_path):
    trace = tmp_path / "crossing.etrace"
    output = tmp_path / "crossing.txt"
    trace.write_bytes(
        etrace_arch(guest_bits=64)
        + etrace_exec64(duration=3, start=0x1000, end=0x100C)
    )

    result = run_etrace(
        "--trace",
        trace,
        "--trace-output",
        output,
        "--elf",
        FIXTURE,
        "--address-map",
        "1004:2000:4",
    )

    assert result.returncode == 0
    assert output.read_text(encoding="ascii").splitlines()[-3:] == [
        "E0 1000 1004",
        "E0 runtime=1004-1008 linked=2000-2004",
        "E0 1008 100c",
    ]


def test_address_map_requires_elf(run_etrace, tmp_path):
    trace = tmp_path / "trace.hex"
    trace.write_text("1000\n", encoding="ascii")

    result = run_etrace(
        "--trace",
        trace,
        "--trace-in-format",
        "ascii-hex",
        "--trace-output",
        "none",
        "--address-map",
        "1000:2000:4",
    )

    assert result.returncode != 0
    assert "Address maps require --elf" in result.stderr
