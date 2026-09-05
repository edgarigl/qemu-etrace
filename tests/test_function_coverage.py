from pathlib import Path
import shutil
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / ".test-build" / "inline-function-fixture"
DUPLICATE_FIXTURE = ROOT / ".test-build" / "duplicate-inline-fixture"


def symbol_range(name, binary=FIXTURE):
    result = subprocess.run(
        ["nm", "-S", str(binary)],
        text=True,
        capture_output=True,
        check=True,
    )
    for line in result.stdout.splitlines():
        fields = line.split(maxsplit=3)
        if len(fields) == 4 and fields[3] == name:
            return int(fields[0], 16), int(fields[1], 16)
    raise AssertionError(f"symbol {name!r} not found")


def inline_body_addresses(
    binary=FIXTURE,
    caller="call_inline_helper",
    inline="inline_helper",
):
    start, size = symbol_range(caller, binary)
    addresses = []
    for address in range(start, start + size, 4):
        result = subprocess.run(
            [
                "addr2line",
                "-f",
                "-i",
                "-C",
                "-e",
                str(binary),
                hex(address),
            ],
            text=True,
            capture_output=True,
            check=True,
        )
        functions = result.stdout.splitlines()[::2]
        if inline in functions:
            addresses.append(address)
    if not addresses:
        raise AssertionError(f"no address attributed to {inline}")
    return addresses


def function_counts(output):
    counts = {}
    for line in output.read_text(encoding="utf-8").splitlines():
        if line.startswith("FNDA:"):
            count, name = line[5:].split(",", 1)
            counts[name] = int(count)
    return counts


def function_records(output, name):
    suffix = f",{name}"
    return [
        line
        for line in output.read_text(encoding="utf-8").splitlines()
        if line.startswith("FNDA:") and line.endswith(suffix)
    ]


def run_coverage(run_etrace, tmp_path, policy, address, *extra_args):
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
        *extra_args,
    )

    assert result.returncode == 0
    return function_counts(output)


def test_source_policy_counts_inlined_function_body(run_etrace, tmp_path):
    if shutil.which("dwarfdump") is None or shutil.which("addr2line") is None:
        pytest.skip("dwarfdump and addr2line are required")

    address = inline_body_addresses()[0]
    entry_counts = run_coverage(run_etrace, tmp_path, "entry", address)
    source_counts = run_coverage(run_etrace, tmp_path, "source", address)

    assert entry_counts["inline_helper"] == 0
    assert source_counts["inline_helper"] > 0
    assert source_counts["call_inline_helper"] > 0


def test_source_policy_ignores_jump_into_inline_range(run_etrace, tmp_path):
    if shutil.which("dwarfdump") is None or shutil.which("addr2line") is None:
        pytest.skip("dwarfdump and addr2line are required")

    addresses = inline_body_addresses()
    if len(addresses) < 2:
        pytest.skip("compiler emitted only one inline-attributed bucket")

    source_counts = run_coverage(run_etrace, tmp_path, "source", addresses[-1])

    assert source_counts["inline_helper"] == 0


def test_source_policy_deduplicates_retained_inline_symbols(
    run_etrace, tmp_path
):
    if shutil.which("dwarfdump") is None or shutil.which("addr2line") is None:
        pytest.skip("dwarfdump and addr2line are required")

    symbols = subprocess.run(
        ["nm", "-S", str(DUPLICATE_FIXTURE)],
        text=True,
        capture_output=True,
        check=True,
    )
    assert sum(
        line.split(maxsplit=3)[-1] == "shared_inline_helper"
        for line in symbols.stdout.splitlines()
    ) == 2
    caller = inline_body_addresses(
        DUPLICATE_FIXTURE,
        caller="call_inline_helper_a",
        inline="shared_inline_helper",
    )
    trace = tmp_path / "duplicate.hex"
    output = tmp_path / "duplicate.info"
    trace.write_text(f"{caller[0]:x}\n", encoding="ascii")

    result = run_etrace(
        "--trace",
        trace,
        "--trace-in-format",
        "ascii-hex",
        "--trace-output",
        "none",
        "--elf",
        DUPLICATE_FIXTURE,
        "--dwarfdump",
        shutil.which("dwarfdump"),
        "--addr2line",
        shutil.which("addr2line"),
        "--coverage-format",
        "lcov",
        "--coverage-output",
        output,
        "--function-hit-policy",
        "source",
    )

    assert result.returncode == 0
    records = function_records(output, "shared_inline_helper")
    assert len(records) == 1
    assert records[0] == "FNDA:1,shared_inline_helper"
