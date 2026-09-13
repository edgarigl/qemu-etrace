from pathlib import Path
import json
import shutil
import subprocess

import pytest

from tests.test_assembly_fixture import find_x86_compiler, nm_symbols, parse_lcov
from tests.trace_builder import etrace_arch, etrace_exec64


ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def attribution_fixture(tmp_path_factory):
    compiler = find_x86_compiler()
    if compiler is None or shutil.which("dwarfdump") is None:
        pytest.skip("x86 compiler and dwarfdump are required")
    binary = tmp_path_factory.mktemp("attribution") / "fixture"
    subprocess.run(
        [
            compiler, "-g", "-nostdlib", "-no-pie", "-Wl,--build-id=none",
            f"-Wl,-T,{ROOT / 'tests/fixtures/attribution.ld'}",
            ROOT / "tests/fixtures/attribution.S", "-o", binary,
        ],
        text=True, capture_output=True, check=True,
    )
    return binary


def run_attribution(run_etrace, tmp_path, binary, *extra):
    start = nm_symbols(binary)["attribution_sample"][0]
    trace = tmp_path / "input.etrace"
    trace.write_bytes(
        etrace_arch(guest_bits=64)
        + etrace_exec64(start=start, end=start + 2) * 3
        + etrace_exec64(start=start, end=start + 1)
    )
    output = tmp_path / "coverage.info"
    result = run_etrace(
        "--trace", trace, "--trace-output", "none", "--elf", binary,
        "--dwarfdump", shutil.which("dwarfdump"),
        "--coverage-format", "lcov", "--coverage-output", output, *extra,
    )
    return result, output, start


@pytest.mark.parametrize("line_policy", ["address", "function-entry"])
def test_attribution_preserves_aliases_and_partial_ranges(
    run_etrace, tmp_path, attribution_fixture, line_policy
):
    result, output, start = run_attribution(
        run_etrace, tmp_path, attribution_fixture, "--line-hit-policy", line_policy
    )
    assert result.returncode == 0, result.stderr
    baseline = output.read_bytes()
    attribution = tmp_path / "attribution.jsonl"
    result, output, _ = run_attribution(
        run_etrace, tmp_path, attribution_fixture,
        "--line-hit-policy", line_policy, "--coverage-attribution", attribution,
    )
    assert result.returncode == 0, result.stderr
    assert output.read_bytes() == baseline

    rows = [json.loads(line) for line in attribution.read_text().splitlines()]
    assert len(rows) == 8
    assert all(row["version"] == 1 and row["kind"] == "dwarf-line" for row in rows)
    assert all(row["source"].endswith("/tests/fixtures/attribution.c") for row in rows)
    assert not any(row["excluded"] for row in rows)
    line10 = [row for row in rows if row["line"] == 10]
    assert len(line10) == 6
    for column, discriminator, is_stmt in [(3, 7, True), (11, 8, False)]:
        aliases = [row for row in line10 if row["column"] == column]
        assert len(aliases) == 3
        assert all(row["discriminator"] == discriminator for row in aliases)
        assert all(row["is_stmt"] is is_stmt for row in aliases)
        assert all(row["executable"] for row in aliases)
        assert all(int(row["range_start"], 16) == start for row in aliases)
        assert all(int(row["range_end"], 16) == start + 3 for row in aliases)
        assert [(int(row["start"], 16), int(row["end"], 16), row["hits"])
                for row in aliases] == [
            (start, start + 1, 4), (start + 1, start + 2, 3),
            (start + 2, start + 3, 0),
        ]
    line20 = [row for row in rows if row["line"] == 20]
    assert len(line20) == 1
    assert line20[0]["column"] == 5
    assert line20[0]["discriminator"] == 0
    assert line20[0]["is_stmt"] is True
    assert int(line20[0]["start"], 16) == start + 3
    assert int(line20[0]["end"], 16) == start + 4
    assert line20[0]["hits"] == 0
    unloaded = [row for row in rows if row["line"] == 99]
    assert len(unloaded) == 1
    assert unloaded[0]["executable"] is False
    assert unloaded[0]["hits"] == 0

    records = parse_lcov(output)
    assert len(records) == 1
    assert next(iter(records.values()))["lines"] == {10: 4, 20: 0}


def test_attribution_keeps_excluded_evidence(
    run_etrace, tmp_path, attribution_fixture
):
    attribution = tmp_path / "attribution.jsonl"
    result, _, _ = run_attribution(
        run_etrace, tmp_path, attribution_fixture,
        "--coverage-attribution", attribution,
    )
    assert result.returncode == 0, result.stderr
    baseline = [json.loads(line) for line in attribution.read_text().splitlines()]
    source = next(row["source"] for row in baseline if row["line"] == 10)
    excludes = tmp_path / "exclude.txt"
    excludes.write_text(f"{source}:10\n", encoding="utf-8")
    result, output, _ = run_attribution(
        run_etrace, tmp_path, attribution_fixture,
        "--coverage-attribution", attribution, "--exclude", excludes,
    )
    assert result.returncode == 0, result.stderr
    rows = [json.loads(line) for line in attribution.read_text().splitlines()]
    assert rows == [dict(row, excluded=row["line"] == 10) for row in baseline]
    assert next(iter(parse_lcov(output).values()))["lines"] == {20: 0}


@pytest.mark.parametrize("destination", ["missing/output.jsonl", "/dev/full"])
def test_attribution_output_errors_fail(
    run_etrace, tmp_path, attribution_fixture, destination
):
    path = tmp_path / destination
    if destination == "/dev/full" and not path.exists():
        pytest.skip("/dev/full is required")
    result, _, _ = run_attribution(
        run_etrace, tmp_path, attribution_fixture, "--coverage-attribution", path
    )
    assert result.returncode != 0
    assert str(path) in result.stderr
