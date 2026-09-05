from pathlib import Path
import re
import shutil
import subprocess

import pytest

from tests.trace_builder import etrace_arch, etrace_exec64


ROOT = Path(__file__).resolve().parents[1]
SOURCE_A = ROOT / "tests" / "fixtures" / "assembly-boundary-a.S"
SOURCE_B = ROOT / "tests" / "fixtures" / "assembly-boundary-b.S"
LINKER_SCRIPT = ROOT / "tests" / "fixtures" / "assembly-boundary.ld"


def find_x86_compiler():
    for name in ("x86_64-linux-gnu-gcc", "gcc", "cc"):
        compiler = shutil.which(name)
        if compiler is None:
            continue
        target = subprocess.run(
            [compiler, "-dumpmachine"],
            text=True,
            capture_output=True,
            check=True,
        ).stdout.strip()
        if target.startswith("x86_64"):
            return compiler
    return None


@pytest.fixture(scope="module")
def assembly_fixture(tmp_path_factory):
    compiler = find_x86_compiler()
    if compiler is None or shutil.which("dwarfdump") is None:
        pytest.skip("x86 compiler and dwarfdump are required")

    directory = tmp_path_factory.mktemp("assembly-attribution")
    object_a = directory / "boundary-a.o"
    object_b = directory / "boundary-b.o"
    binary = directory / "fixture"
    for source, output in ((SOURCE_A, object_a), (SOURCE_B, object_b)):
        subprocess.run(
            [compiler, "-g", "-x", "assembler", "-c", source, "-o", output],
            text=True,
            capture_output=True,
            check=True,
        )
    subprocess.run(
        [
            compiler,
            "-nostdlib",
            "-no-pie",
            "-Wl,--build-id=none",
            f"-Wl,-T,{LINKER_SCRIPT}",
            object_a,
            object_b,
            "-o",
            binary,
        ],
        text=True,
        capture_output=True,
        check=True,
    )
    return binary


def nm_symbols(binary):
    result = subprocess.run(
        ["nm", "-S", "--defined-only", binary],
        text=True,
        capture_output=True,
        check=True,
    )
    symbols = {}
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) == 4:
            address, size, symbol_type, name = fields
            symbols[name] = (int(address, 16), int(size, 16), symbol_type)
        elif len(fields) == 3:
            address, symbol_type, name = fields
            symbols[name] = (int(address, 16), None, symbol_type)
    return symbols


def line_rows(binary):
    result = subprocess.run(
        ["dwarfdump", "-l", binary],
        text=True,
        capture_output=True,
        check=True,
    )
    rows = []
    pattern = re.compile(r"^(0x[0-9a-f]+)\s+\[\s*(\d+),.*?\]\s+(.*)$")
    for line in result.stdout.splitlines():
        match = pattern.match(line)
        if match:
            rows.append(
                (int(match.group(1), 16), int(match.group(2)), match.group(3))
            )
    return rows


def test_assembly_fixture_symbol_shapes(assembly_fixture):
    symbols = nm_symbols(assembly_fixture)

    assert symbols["boundary_source"][1] > 0
    assert symbols["boundary_target"][1] > 0
    assert symbols["macro_thunk_one"][1] > 0
    assert symbols["macro_thunk_two"][1] > 0
    assert symbols["macro_thunk_three"][1] > 0
    assert symbols["repeated_line"][1] > 0
    assert symbols["zero_sized_entry"][1] in (None, 0)
    assert "discarded_function" not in symbols


def test_assembly_fixture_line_sequence_shapes(assembly_fixture):
    symbols = nm_symbols(assembly_fixture)
    rows = line_rows(assembly_fixture)
    target = symbols["boundary_target"][0]
    target_end = target + symbols["boundary_target"][1]
    macro_starts = [
        symbols[name][0]
        for name in ("macro_thunk_one", "macro_thunk_two", "macro_thunk_three")
    ]

    assert any(address == target and "ET" in flags for address, _, flags in rows)
    assert not any(
        target <= address < target_end and line == 20
        for address, line, _ in rows
        if address == target
    )
    assert any(
        target < address < target_end and line == 20
        for address, line, _ in rows
    )
    assert [address for address, line, _ in rows if line == 30] == [
        macro_starts[0]
    ]
    assert macro_starts == sorted(macro_starts)
    assert any(address == 0 and line == 60 for address, line, _ in rows)
    assert len([address for address, line, _ in rows if line == 70]) == 2


def parse_lcov(path):
    records = {}
    current = None
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("SF:"):
            current = {"functions": {}, "function_hits": {}, "lines": {}}
            records[line[3:]] = current
        elif line.startswith("FN:"):
            line_number, name = line[3:].split(",", 1)
            current["functions"][name] = int(line_number)
        elif line.startswith("FNDA:"):
            count, name = line[5:].split(",", 1)
            current["function_hits"][name] = int(count)
        elif line.startswith("DA:"):
            number, count = line[3:].split(",", 1)
            current["lines"][int(number)] = int(count)
    return records


def source_record(records, suffix):
    matches = [record for name, record in records.items() if name.endswith(suffix)]
    assert len(matches) == 1
    return matches[0]


def run_lcov(run_etrace, tmp_path, assembly_fixture, start, end):
    trace = tmp_path / "assembly.etrace"
    output = tmp_path / "assembly.info"
    trace.write_bytes(
        etrace_arch(guest_bits=64) + etrace_exec64(start=start, end=end)
    )
    result = run_etrace(
        "--trace",
        trace,
        "--trace-output",
        "none",
        "--elf",
        assembly_fixture,
        "--dwarfdump",
        shutil.which("dwarfdump"),
        "--coverage-format",
        "lcov",
        "--coverage-output",
        output,
    )
    assert result.returncode == 0, result.stderr
    return parse_lcov(output)


def test_end_sequence_does_not_map_next_function(
    run_etrace, tmp_path, assembly_fixture
):
    symbols = nm_symbols(assembly_fixture)
    start, size, _ = symbols["boundary_target"]
    records = run_lcov(run_etrace, tmp_path, assembly_fixture, start, start + size)
    source_a = source_record(records, "assembly-boundary-a.S")
    source_b = source_record(records, "assembly-boundary-b.S")

    assert source_a["lines"][12] == 0
    assert "boundary_target" not in source_a["functions"]
    assert source_b["lines"][20] > 0


def test_function_declaration_uses_first_body_row(
    run_etrace, tmp_path, assembly_fixture
):
    symbols = nm_symbols(assembly_fixture)
    start, size, _ = symbols["boundary_target"]
    records = run_lcov(run_etrace, tmp_path, assembly_fixture, start, start + size)
    source_b = source_record(records, "assembly-boundary-b.S")

    assert source_b["functions"]["boundary_target"] == 20
    assert source_b["function_hits"]["boundary_target"] == 1


def test_line_hits_use_maximum_address_count(run_etrace, tmp_path, assembly_fixture):
    symbols = nm_symbols(assembly_fixture)
    start, size, _ = symbols["repeated_line"]
    rows = [address for address, line, _ in line_rows(assembly_fixture) if line == 70]
    assert len(rows) == 2

    trace = tmp_path / "repeated-line.etrace"
    output = tmp_path / "repeated-line.info"
    trace.write_bytes(
        etrace_arch(guest_bits=64)
        + etrace_exec64(start=rows[0], end=rows[0] + 1)
        + etrace_exec64(start=rows[1], end=rows[1] + 1)
        + etrace_exec64(start=rows[1], end=rows[1] + 1)
    )
    result = run_etrace(
        "--trace",
        trace,
        "--trace-output",
        "none",
        "--elf",
        assembly_fixture,
        "--dwarfdump",
        shutil.which("dwarfdump"),
        "--coverage-format",
        "lcov",
        "--coverage-output",
        output,
    )
    assert result.returncode == 0, result.stderr
    source_b = source_record(parse_lcov(output), "assembly-boundary-b.S")

    assert start <= rows[0] < start + size
    assert start <= rows[1] < start + size
    assert source_b["lines"][70] == 2
