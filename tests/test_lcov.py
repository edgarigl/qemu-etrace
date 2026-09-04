from pathlib import Path
import shutil
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[1]
COVERAGE_FIXTURE = ROOT / ".test-build" / "coverage-fixture"


def symbol_address(binary, name):
    result = subprocess.run(
        ["nm", "-S", str(binary)],
        text=True,
        capture_output=True,
        check=True,
    )
    for line in result.stdout.splitlines():
        fields = line.split(maxsplit=3)
        if len(fields) == 4 and fields[3] == name:
            return fields[0]
    raise AssertionError(f"symbol {name!r} not found in {binary}")


def lcov_record(output, source):
    for record in output.read_text(encoding="utf-8").split("end_of_record"):
        lines = record.splitlines()
        if f"SF:{source}" in lines:
            return lines
    raise AssertionError(f"LCOV record for {source} not found")


def test_lcov_counts_only_executed_lines_as_hit(run_etrace, tmp_path):
    if shutil.which("dwarfdump") is None:
        pytest.skip("dwarfdump is required for LCOV generation")

    trace = tmp_path / "trace.hex"
    output = tmp_path / "coverage.info"
    trace.write_text(f"{symbol_address(COVERAGE_FIXTURE, 'covered')}\n", encoding="ascii")

    result = run_etrace(
        "--trace",
        trace,
        "--trace-in-format",
        "ascii-hex",
        "--trace-output",
        "none",
        "--elf",
        COVERAGE_FIXTURE,
        "--dwarfdump",
        shutil.which("dwarfdump"),
        "--coverage-format",
        "lcov",
        "--coverage-output",
        output,
    )

    assert result.returncode == 0
    source = Path(__file__).parent / "fixtures" / "coverage.c"
    record = lcov_record(output, source)
    line_counts = [int(line.rsplit(",", 1)[1]) for line in record if line.startswith("DA:")]
    lines_found = int(next(line[3:] for line in record if line.startswith("LF:")))
    lines_hit = int(next(line[3:] for line in record if line.startswith("LH:")))

    assert lines_found == len(line_counts)
    assert lines_hit == sum(count > 0 for count in line_counts)
    assert 0 < lines_hit < lines_found
