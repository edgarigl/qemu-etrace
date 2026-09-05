from pathlib import Path
import shutil
import subprocess
from types import SimpleNamespace

import pytest

from tests.trace_builder import etrace_arch, etrace_exec64


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "tests/fixtures/x86-variable-length.s"
BYTE_COVERAGE_BUG = pytest.mark.xfail(
    strict=True,
    reason="coverage is stored in four-byte buckets",
)


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
def x86_fixture(tmp_path_factory):
    tools = {
        "cc": find_x86_compiler(),
        "nm": shutil.which("x86_64-linux-gnu-nm") or shutil.which("nm"),
        "objdump": shutil.which("x86_64-linux-gnu-objdump")
        or shutil.which("objdump"),
        "addr2line": shutil.which("x86_64-linux-gnu-addr2line")
        or shutil.which("addr2line"),
        "dwarfdump": shutil.which("dwarfdump"),
    }
    missing = [name for name, path in tools.items() if path is None]
    if missing:
        pytest.skip(f"x86 coverage fixture requires: {', '.join(missing)}")

    binary = tmp_path_factory.mktemp("x86-coverage") / "fixture"
    subprocess.run(
        [
            tools["cc"],
            "-g",
            "-nostdlib",
            "-no-pie",
            "-Wl,--build-id=none",
            "-Wl,-e,x86_coverage_fixture",
            SOURCE,
            "-o",
            binary,
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=True,
    )
    symbols = subprocess.run(
        [tools["nm"], "-S", binary],
        text=True,
        capture_output=True,
        check=True,
    )
    for line in symbols.stdout.splitlines():
        fields = line.split(maxsplit=3)
        if len(fields) == 4 and fields[3] == "x86_coverage_fixture":
            start = int(fields[0], 16)
            size = int(fields[1], 16)
            break
    else:
        raise AssertionError("x86_coverage_fixture symbol not found")

    assert start % 4 == 1
    assert size == 11
    disassembly = subprocess.run(
        [tools["objdump"], "-d", binary],
        text=True,
        capture_output=True,
        check=True,
    )
    instructions = []
    for line in disassembly.stdout.splitlines():
        fields = line.split("\t")
        if len(fields) < 3 or not fields[0].strip().endswith(":"):
            continue
        address = int(fields[0].strip()[:-1], 16)
        if start <= address < start + size:
            instructions.append((address - start, len(fields[1].split())))
    return SimpleNamespace(
        binary=binary,
        start=start,
        tools=tools,
        instructions=instructions,
    )


def run_lcov(run_etrace, tmp_path, fixture, start, end, policy="entry"):
    trace = tmp_path / f"{policy}-{start:x}-{end:x}.etrace"
    output = tmp_path / f"{policy}-{start:x}-{end:x}.info"
    trace.write_bytes(
        etrace_arch(guest_bits=64)
        + etrace_exec64(start=start, end=end)
    )
    result = run_etrace(
        "--trace",
        trace,
        "--trace-output",
        "none",
        "--elf",
        fixture.binary,
        "--nm",
        fixture.tools["nm"],
        "--addr2line",
        fixture.tools["addr2line"],
        "--dwarfdump",
        fixture.tools["dwarfdump"],
        "--coverage-format",
        "lcov",
        "--coverage-output",
        output,
        "--function-hit-policy",
        policy,
    )
    assert result.returncode == 0, result.stderr

    lines = {}
    functions = {}
    for line in output.read_text(encoding="utf-8").splitlines():
        if line.startswith("DA:"):
            number, count = line[3:].split(",", 1)
            lines[int(number)] = int(count)
        elif line.startswith("FNDA:"):
            count, name = line[5:].split(",", 1)
            functions[name] = int(count)
    return lines, functions


def test_x86_fixture_has_variable_length_instructions(x86_fixture):
    assert x86_fixture.instructions == [
        (0, 1),
        (1, 2),
        (3, 4),
        (7, 1),
        (8, 2),
        (10, 1),
    ]


@BYTE_COVERAGE_BUG
def test_two_byte_tb_marks_its_source_line(run_etrace, tmp_path, x86_fixture):
    start = x86_fixture.start

    lines, _ = run_lcov(run_etrace, tmp_path, x86_fixture, start + 1, start + 3)

    assert lines[11] == 1


@BYTE_COVERAGE_BUG
def test_unaligned_tb_does_not_hit_preceding_lines(
    run_etrace, tmp_path, x86_fixture
):
    start = x86_fixture.start

    lines, _ = run_lcov(run_etrace, tmp_path, x86_fixture, start + 3, start + 7)

    assert lines[10] == 0
    assert lines[11] == 0
    assert lines[12] == 1


@BYTE_COVERAGE_BUG
def test_unaligned_tb_marks_its_final_instruction(run_etrace, tmp_path, x86_fixture):
    start = x86_fixture.start

    lines, _ = run_lcov(run_etrace, tmp_path, x86_fixture, start + 1, start + 8)

    assert lines[10] == 0
    assert lines[11] == 1
    assert lines[12] == 1
    assert lines[13] == 1


@BYTE_COVERAGE_BUG
@pytest.mark.parametrize("policy", ["entry", "source"])
def test_short_unaligned_function_entry_is_counted(
    run_etrace, tmp_path, x86_fixture, policy
):
    start = x86_fixture.start

    _, functions = run_lcov(
        run_etrace,
        tmp_path,
        x86_fixture,
        start,
        start + 1,
        policy,
    )

    assert functions["x86_coverage_fixture"] == 1
