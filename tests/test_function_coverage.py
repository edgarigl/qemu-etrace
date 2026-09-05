from pathlib import Path
import shutil
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / ".test-build" / "inline-function-fixture"


def symbol_range(name):
    result = subprocess.run(
        ["nm", "-S", str(FIXTURE)],
        text=True,
        capture_output=True,
        check=True,
    )
    for line in result.stdout.splitlines():
        fields = line.split(maxsplit=3)
        if len(fields) == 4 and fields[3] == name:
            return int(fields[0], 16), int(fields[1], 16)
    raise AssertionError(f"symbol {name!r} not found")


def inline_body_address():
    start, size = symbol_range("call_inline_helper")
    for address in range(start, start + size, 4):
        result = subprocess.run(
            [
                "addr2line",
                "-f",
                "-i",
                "-C",
                "-e",
                str(FIXTURE),
                hex(address),
            ],
            text=True,
            capture_output=True,
            check=True,
        )
        functions = result.stdout.splitlines()[::2]
        if "inline_helper" in functions:
            return address
    raise AssertionError("no address attributed to inline_helper")


def function_counts(output):
    counts = {}
    for line in output.read_text(encoding="utf-8").splitlines():
        if line.startswith("FNDA:"):
            count, name = line[5:].split(",", 1)
            counts[name] = int(count)
    return counts


def run_coverage(run_etrace, tmp_path, policy, address):
    trace = tmp_path / f"{policy}.hex"
    output = tmp_path / f"{policy}.info"
    trace.write_text(f"{address:x}\n", encoding="ascii")

    result = run_etrace(
        "--trace",
        trace,
        "--trace-in-format",
        "ascii-hex",
        "--trace-output",
        "none",
        "--elf",
        FIXTURE,
        "--dwarfdump",
        shutil.which("dwarfdump"),
        "--addr2line",
        shutil.which("addr2line"),
        "--coverage-format",
        "lcov",
        "--coverage-output",
        output,
        "--function-hit-policy",
        policy,
    )

    assert result.returncode == 0
    return function_counts(output)


def test_source_policy_counts_inlined_function_body(run_etrace, tmp_path):
    if shutil.which("dwarfdump") is None or shutil.which("addr2line") is None:
        pytest.skip("dwarfdump and addr2line are required")

    address = inline_body_address()
    entry_counts = run_coverage(run_etrace, tmp_path, "entry", address)
    source_counts = run_coverage(run_etrace, tmp_path, "source", address)

    assert entry_counts["inline_helper"] == 0
    assert source_counts["inline_helper"] > 0
    assert source_counts["call_inline_helper"] > 0
