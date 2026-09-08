from pathlib import Path
import shutil
import struct
import subprocess
from types import SimpleNamespace

import pytest

from tests.trace_builder import (
    ETRACE_INFO_F_FILTERED,
    ETRACE_INFO_F_FINAL_STATUS,
    ETRACE_TYPE_CONTEXT_GAP,
    ETRACE_TYPE_DISCONTINUITY,
    ETRACE_TYPE_TB_EXEC,
    etrace_arch,
    etrace_context_gap,
    etrace_discontinuity,
    etrace_exec64,
    etrace_info,
    etrace_status_v1,
    etrace_tb_def,
    etrace_tb_exec,
)


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "tests/fixtures/x86-variable-length.s"


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
    code = bytearray()
    for line in disassembly.stdout.splitlines():
        fields = line.split("\t")
        if len(fields) < 3 or not fields[0].strip().endswith(":"):
            continue
        address = int(fields[0].strip()[:-1], 16)
        if start <= address < start + size:
            encoded = bytes.fromhex("".join(fields[1].split()))
            instructions.append((address - start, len(encoded)))
            code.extend(encoded)
    return SimpleNamespace(
        binary=binary,
        start=start,
        tools=tools,
        instructions=instructions,
        code=bytes(code),
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

    return parse_lcov(output)


def parse_lcov(output):
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


def run_v1_lcov(run_etrace, tmp_path, fixture, trace, *extra_args):
    output = tmp_path / f"{trace.stem}.info"
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
        *extra_args,
    )
    return result, parse_lcov(output) if output.exists() else ({}, {})


def test_etrace_coverage_uses_byte_addresses(run_etrace, tmp_path, x86_fixture):
    start = x86_fixture.start
    trace = tmp_path / "byte-coverage.etrace"
    output = tmp_path / "byte-coverage.txt"
    trace.write_bytes(
        etrace_arch(guest_bits=64)
        + etrace_exec64(duration=2, start=start + 1, end=start + 3)
    )

    result = run_etrace(
        "--trace",
        trace,
        "--trace-output",
        "none",
        "--elf",
        x86_fixture.binary,
        "--nm",
        x86_fixture.tools["nm"],
        "--dwarfdump",
        x86_fixture.tools["dwarfdump"],
        "--coverage-format",
        "etrace",
        "--coverage-output",
        output,
    )
    assert result.returncode == 0, result.stderr

    coverage = {
        int(fields[1], 16): int(fields[0])
        for line in output.read_text(encoding="utf-8").splitlines()
        if len(fields := line.split()) >= 3
        and fields[2] == "x86_coverage_fixture"
    }
    assert len(coverage) == 11
    assert coverage[start] == 0
    assert coverage[start + 1] == 1
    assert coverage[start + 2] == 1
    assert coverage[start + 3] == 0


def test_v1_partial_tb_matches_execution_range(run_etrace, tmp_path, x86_fixture):
    if shutil.which("dwarfdump") is None:
        pytest.skip("dwarfdump is required for LCOV generation")

    start = x86_fixture.start
    executed_insns = 3
    end = start + sum(size for _, size in x86_fixture.instructions[:executed_insns])
    v1_trace = tmp_path / "v1-tb.etrace"
    v1_trace.write_bytes(
        etrace_info(major=1)
        + etrace_tb_def(
            tb_id=11,
            vaddr=start,
            insns=tuple(x86_fixture.instructions),
        )
        + etrace_tb_exec(tb_id=11, insn_count=executed_insns)
    )

    legacy_lines, legacy_functions = run_lcov(
        run_etrace, tmp_path, x86_fixture, start, end
    )
    output = tmp_path / "v1.info"
    result = run_etrace(
        "--trace",
        v1_trace,
        "--trace-output",
        "none",
        "--elf",
        x86_fixture.binary,
        "--nm",
        x86_fixture.tools["nm"],
        "--addr2line",
        x86_fixture.tools["addr2line"],
        "--dwarfdump",
        x86_fixture.tools["dwarfdump"],
        "--coverage-format",
        "lcov",
        "--coverage-output",
        output,
    )
    assert result.returncode == 0, result.stderr
    v1_lines = {}
    v1_functions = {}
    for line in output.read_text(encoding="utf-8").splitlines():
        if line.startswith("DA:"):
            number, count = line[3:].split(",", 1)
            v1_lines[int(number)] = int(count)
        elif line.startswith("FNDA:"):
            count, name = line[5:].split(",", 1)
            v1_functions[name] = int(count)

    assert v1_lines == legacy_lines
    assert v1_functions == legacy_functions


def test_v1_auto_map_replays_early_physical_execution(
    run_etrace, tmp_path, x86_fixture
):
    linked = x86_fixture.start
    physical = 0x200000
    early = physical
    instructions = tuple(x86_fixture.instructions[:3])
    code_len = sum(size for _, size in instructions)
    code = x86_fixture.code[:code_len]
    legacy = tmp_path / "physical-alias-expected.etrace"
    legacy.write_bytes(
        etrace_arch(guest_bits=64)
        + etrace_exec64(start=linked, end=linked + code_len)
        + etrace_exec64(start=linked, end=linked + code_len)
    )
    expected_result, expected = run_v1_lcov(
        run_etrace, tmp_path, x86_fixture, legacy
    )
    assert expected_result.returncode == 0, expected_result.stderr
    trace = tmp_path / "physical-alias.etrace"
    trace.write_bytes(
        etrace_info(major=1)
        + etrace_tb_def(
            tb_id=1,
            vaddr=early,
            insns=instructions,
            mappings=((0, code_len, physical),),
            code=code,
        )
        + etrace_tb_exec(tb_id=1, sequence=1, insn_count=len(instructions))
        + etrace_tb_exec(tb_id=1, sequence=2, insn_count=len(instructions))
        + etrace_tb_def(
            tb_id=2,
            vaddr=linked,
            insns=instructions,
            mappings=((0, code_len, physical),),
            code=code,
        )
    )

    result, actual = run_v1_lcov(
        run_etrace, tmp_path, x86_fixture, trace, "--auto-map"
    )

    assert result.returncode == 0, result.stderr
    assert "unresolved aggregates" not in result.stderr
    assert actual == expected

    ordered_result, ordered = run_v1_lcov(
        run_etrace,
        tmp_path,
        x86_fixture,
        trace,
        "--auto-map",
        "--preserve-order",
    )
    assert ordered_result.returncode == 0, ordered_result.stderr
    assert ordered == expected


@pytest.mark.parametrize("ordered", [False, True])
@pytest.mark.parametrize("explicit", [False, True])
@pytest.mark.parametrize("matching", [False, True])
def test_v1_auto_map_checks_short_mapped_code(
    run_etrace, tmp_path, x86_fixture, ordered, explicit, matching
):
    linked = x86_fixture.start
    runtime = 0x30000000 if explicit else linked
    instructions = tuple(x86_fixture.instructions[:3])
    code_len = sum(size for _, size in instructions)
    code = x86_fixture.code[:code_len] if matching else b"\xcc" * code_len
    trace = tmp_path / "short-mapped-code.etrace"
    trace.write_bytes(
        etrace_info(major=1)
        + etrace_tb_def(vaddr=runtime, insns=instructions, code=code)
        + etrace_tb_exec(insn_count=len(instructions))
    )
    extra_args = ["--preserve-order"] if ordered else []
    if explicit:
        extra_args += ["--address-map", f"{runtime:x}:{linked:x}:{code_len:x}"]

    result, (lines, functions) = run_v1_lcov(
        run_etrace, tmp_path, x86_fixture, trace, "--auto-map", *extra_args
    )

    assert result.returncode == 0, result.stderr
    assert functions["x86_coverage_fixture"] == int(matching)
    assert lines[10] == lines[11] == lines[12] == int(matching)
    assert ("unresolved" in result.stderr) == (not matching)


@pytest.mark.parametrize("ordered", [False, True])
def test_v1_auto_map_keeps_unique_code_unresolved(
    run_etrace, tmp_path, x86_fixture, ordered
):
    physical = 0x200000
    trace = tmp_path / "unverified-code.etrace"
    trace.write_bytes(
        etrace_info(major=1)
        + etrace_tb_def(
            tb_id=1,
            vaddr=0x30000000,
            insns=tuple(x86_fixture.instructions),
            mappings=((0, len(x86_fixture.code), physical),),
            code=x86_fixture.code,
        )
        + etrace_tb_exec(
            tb_id=1, sequence=1, insn_count=len(x86_fixture.instructions)
        )
        # A unique match must not seed a binding for a short physical alias.
        + etrace_tb_def(
            tb_id=2,
            vaddr=physical,
            insns=tuple(x86_fixture.instructions[:3]),
            mappings=((0, 7, physical),),
            code=x86_fixture.code[:7],
        )
        + etrace_tb_exec(tb_id=2, sequence=2, insn_count=3)
    )
    extra_args = ("--preserve-order",) if ordered else ()

    result, (lines, functions) = run_v1_lcov(
        run_etrace, tmp_path, x86_fixture, trace, "--auto-map", *extra_args
    )

    assert result.returncode == 0, result.stderr
    assert functions["x86_coverage_fixture"] == 0
    assert lines and not any(lines.values())
    assert "1 unverified code-match candidates" in result.stderr
    if ordered:
        assert "retained 2 unresolved execution boundaries" in result.stderr
    else:
        assert "2 execution events in 2 unresolved aggregates" in result.stderr


@pytest.mark.parametrize("ordered", [False, True])
@pytest.mark.parametrize("explicit", [False, True])
def test_v1_auto_map_replays_code_candidate_after_anchor(
    run_etrace, tmp_path, x86_fixture, ordered, explicit
):
    linked = x86_fixture.start
    runtime = 0x30000000
    physical = 0x200000
    anchor = 0x40000000 if explicit else linked
    code_len = len(x86_fixture.code)
    expected = run_lcov(
        run_etrace,
        tmp_path,
        x86_fixture,
        linked,
        linked + code_len,
    )
    trace = tmp_path / "anchored-code.etrace"
    trace.write_bytes(
        etrace_info(major=1)
        + etrace_tb_def(
            tb_id=1,
            vaddr=runtime,
            insns=tuple(x86_fixture.instructions),
            mappings=((0, code_len, physical),),
            code=x86_fixture.code,
        )
        + etrace_tb_exec(
            tb_id=1,
            sequence=1,
            insn_count=len(x86_fixture.instructions),
        )
        + etrace_tb_def(
            tb_id=2,
            vaddr=anchor,
            insns=tuple(x86_fixture.instructions),
            mappings=((0, code_len, physical),),
            code=x86_fixture.code,
        )
    )
    extra_args = ["--preserve-order"] if ordered else []
    if explicit:
        extra_args += ["--address-map", f"{anchor:x}:{linked:x}:{code_len:x}"]

    result, actual = run_v1_lcov(
        run_etrace, tmp_path, x86_fixture, trace, "--auto-map", *extra_args
    )

    assert result.returncode == 0, result.stderr
    assert "unresolved" not in result.stderr
    assert "unverified code-match candidates" not in result.stderr
    assert actual == expected


@pytest.mark.parametrize("ordered", [False, True])
def test_v1_auto_map_requires_anchor_to_cover_candidate(
    run_etrace, tmp_path, x86_fixture, ordered
):
    physical = 0x200000
    trace = tmp_path / "partial-anchor.etrace"
    trace.write_bytes(
        etrace_info(major=1)
        + etrace_tb_def(
            tb_id=1,
            vaddr=0x30000000,
            insns=tuple(x86_fixture.instructions),
            mappings=((0, len(x86_fixture.code), physical),),
            code=x86_fixture.code,
        )
        + etrace_tb_exec(
            tb_id=1, sequence=1, insn_count=len(x86_fixture.instructions)
        )
        # This verified binding covers only the candidate's first seven bytes.
        + etrace_tb_def(
            tb_id=2,
            vaddr=x86_fixture.start,
            insns=tuple(x86_fixture.instructions[:3]),
            mappings=((0, 7, physical),),
            code=x86_fixture.code[:7],
        )
    )
    extra_args = ("--preserve-order",) if ordered else ()

    result, (lines, functions) = run_v1_lcov(
        run_etrace, tmp_path, x86_fixture, trace, "--auto-map", *extra_args
    )

    assert result.returncode == 0, result.stderr
    assert functions["x86_coverage_fixture"] == 0
    assert lines and not any(lines.values())
    assert "1 unverified code-match candidates" in result.stderr


def test_v1_auto_map_enforces_unresolved_limit(
    run_etrace, tmp_path, x86_fixture
):
    trace = tmp_path / "unresolved-limit.etrace"
    trace.write_bytes(
        etrace_info(major=1)
        + etrace_tb_def(
            tb_id=1,
            vaddr=0x40000000,
            insns=((0, 4), (4, 4)),
            code=b"\xff" * 8,
        )
        + etrace_tb_exec(tb_id=1, sequence=1, insn_count=1)
        + etrace_tb_exec(tb_id=1, sequence=2, insn_count=2)
    )

    result = run_etrace(
        "--trace",
        trace,
        "--trace-output",
        "none",
        "--elf",
        x86_fixture.binary,
        "--auto-map",
        "--unresolved-limit",
        "1",
    )

    assert result.returncode != 0
    assert "unresolved execution limit exceeded" in result.stderr


def test_v1_auto_map_keeps_ambiguous_code_unresolved(
    run_etrace, tmp_path, x86_fixture
):
    code = x86_fixture.code[:8]
    trace = tmp_path / "ambiguous-code.etrace"
    trace.write_bytes(
        etrace_info(major=1)
        + etrace_tb_def(
            tb_id=1,
            vaddr=0x50000000,
            insns=((0, 8),),
            code=code,
        )
        + etrace_tb_exec(tb_id=1, sequence=1, insn_count=1)
    )

    result, (_, functions) = run_v1_lcov(
        run_etrace, tmp_path, x86_fixture, trace, "--auto-map"
    )

    assert result.returncode == 0, result.stderr
    assert "1 ambiguous TBs" in result.stderr
    assert functions["x86_coverage_fixture"] == 0

    output = tmp_path / "ambiguous-ordered.txt"
    ordered = run_etrace(
        "--trace",
        trace,
        "--trace-output",
        output,
        "--elf",
        x86_fixture.binary,
        "--auto-map",
        "--preserve-order",
    )
    assert ordered.returncode == 0, ordered.stderr
    assert "Ordered replay retained 1 unresolved execution boundaries" in (
        ordered.stderr
    )
    assert any(
        line.startswith("U0 sequence=1 tb=1")
        for line in output.read_text(encoding="ascii").splitlines()
    )


def test_v1_ordered_replay_preserves_dynamic_events(
    run_etrace, tmp_path, x86_fixture
):
    linked = x86_fixture.start
    physical = 0x600000
    early_insns = tuple(x86_fixture.instructions[:3])
    early_len = sum(size for _, size in early_insns)
    tail_insns = ((0, 2), (2, 1))
    trace = tmp_path / "ordered-events.etrace"
    output = tmp_path / "ordered-events.txt"
    spool = tmp_path / "ordered-events.bin"
    trace.write_bytes(
        etrace_info(
            major=1,
            attributes=ETRACE_INFO_F_FILTERED | ETRACE_INFO_F_FINAL_STATUS,
        )
        + etrace_tb_def(
            tb_id=1,
            vaddr=physical,
            insns=early_insns,
            mappings=((0, early_len, physical),),
            code=x86_fixture.code[:early_len],
        )
        + etrace_tb_exec(
            tb_id=1, sequence=1, insn_count=len(early_insns), unit_id=1
        )
        + etrace_discontinuity(
            from_pc=physical + early_len,
            to_pc=linked,
            kind=1,
            unit_id=1,
        )
        + etrace_context_gap(sequence=2, filtered_execs=1, unit_id=1)
        + etrace_tb_def(
            tb_id=2,
            vaddr=linked,
            insns=early_insns,
            mappings=((0, early_len, physical),),
            code=x86_fixture.code[:early_len],
        )
        + etrace_tb_def(
            tb_id=3,
            vaddr=linked + 8,
            insns=tail_insns,
            code=x86_fixture.code[8:11],
        )
        + etrace_tb_exec(
            tb_id=3, sequence=3, insn_count=2, unit_id=1
        )
        + etrace_status_v1()
    )

    result = run_etrace(
        "--trace",
        trace,
        "--trace-output",
        output,
        "--elf",
        x86_fixture.binary,
        "--auto-map",
        "--preserve-order",
        "--event-spool",
        spool,
    )

    assert result.returncode == 0, result.stderr
    dynamic = [
        line.split()[0][0]
        for line in output.read_text(encoding="ascii").splitlines()
        if line and line[0] in "EDGU"
    ]
    assert dynamic == ["E", "D", "G", "E"]
    assert spool.stat().st_size > 0
    records = []
    data = spool.read_bytes()
    offset = 0
    while offset < len(data):
        record_type, _, payload_len = struct.unpack_from("=HHI", data, offset)
        records.append(record_type)
        offset += 8 + payload_len
    assert records == [
        ETRACE_TYPE_TB_EXEC,
        ETRACE_TYPE_DISCONTINUITY,
        ETRACE_TYPE_CONTEXT_GAP,
        ETRACE_TYPE_TB_EXEC,
    ]
    assert output.read_text(encoding="ascii").splitlines()[-1].startswith(
        "S1 filtered-exec="
    )


def test_v1_ordered_replay_preserves_vcpu_interleaving(
    run_etrace, tmp_path, x86_fixture
):
    trace = tmp_path / "ordered-vcpus.etrace"
    output = tmp_path / "ordered-vcpus.txt"
    trace.write_bytes(
        etrace_info(major=1)
        + etrace_tb_def(
            tb_id=1,
            vaddr=x86_fixture.start,
            insns=tuple(x86_fixture.instructions),
            code=x86_fixture.code,
        )
        + etrace_tb_exec(tb_id=1, sequence=1, insn_count=1, unit_id=1)
        + etrace_tb_exec(tb_id=1, sequence=9, insn_count=2, unit_id=2)
        + etrace_tb_exec(tb_id=1, sequence=2, insn_count=3, unit_id=1)
    )

    result = run_etrace(
        "--trace",
        trace,
        "--trace-output",
        output,
        "--elf",
        x86_fixture.binary,
        "--auto-map",
        "--preserve-order",
    )

    assert result.returncode == 0, result.stderr
    units = [
        line.split()[0]
        for line in output.read_text(encoding="ascii").splitlines()
        if line.startswith("E")
    ]
    assert units == ["E1", "E2", "E1"]


def test_v1_ordered_replay_enforces_spool_limit(
    run_etrace, tmp_path, x86_fixture
):
    trace = tmp_path / "ordered-limit.etrace"
    trace.write_bytes(
        etrace_info(major=1)
        + etrace_tb_def(
            tb_id=1,
            vaddr=x86_fixture.start,
            insns=((0, 1),),
            code=x86_fixture.code[:1],
        )
        + etrace_tb_exec(tb_id=1, sequence=1, insn_count=1)
    )

    result = run_etrace(
        "--trace",
        trace,
        "--trace-output",
        "none",
        "--elf",
        x86_fixture.binary,
        "--auto-map",
        "--preserve-order",
        "--event-spool-limit",
        "1",
    )

    assert result.returncode != 0
    assert "event spool limit exceeded" in result.stderr


def test_v1_ordered_replay_reports_spool_io_failure(
    run_etrace, tmp_path, x86_fixture
):
    full = Path("/dev/full")
    if not full.exists():
        pytest.skip("event spool I/O failure test requires /dev/full")
    trace = tmp_path / "ordered-io-error.etrace"
    trace.write_bytes(
        etrace_info(major=1)
        + etrace_tb_def(
            tb_id=1,
            vaddr=x86_fixture.start,
            insns=((0, 1),),
            code=x86_fixture.code[:1],
        )
        + etrace_tb_exec(tb_id=1, sequence=1, insn_count=1)
    )

    result = run_etrace(
        "--trace",
        trace,
        "--trace-output",
        "none",
        "--elf",
        x86_fixture.binary,
        "--auto-map",
        "--preserve-order",
        "--event-spool",
        full,
    )

    assert result.returncode != 0
    assert "ordered event spool" in result.stderr.lower()


def test_x86_fixture_has_variable_length_instructions(x86_fixture):
    assert x86_fixture.instructions == [
        (0, 1),
        (1, 2),
        (3, 4),
        (7, 1),
        (8, 2),
        (10, 1),
    ]


def test_two_byte_tb_marks_its_source_line(run_etrace, tmp_path, x86_fixture):
    start = x86_fixture.start

    lines, _ = run_lcov(run_etrace, tmp_path, x86_fixture, start + 1, start + 3)

    assert lines[11] == 1


def test_unaligned_tb_does_not_hit_preceding_lines(
    run_etrace, tmp_path, x86_fixture
):
    start = x86_fixture.start

    lines, _ = run_lcov(run_etrace, tmp_path, x86_fixture, start + 3, start + 7)

    assert lines[10] == 0
    assert lines[11] == 0
    assert lines[12] == 1


def test_unaligned_tb_marks_its_final_instruction(run_etrace, tmp_path, x86_fixture):
    start = x86_fixture.start

    lines, _ = run_lcov(run_etrace, tmp_path, x86_fixture, start + 1, start + 8)

    assert lines[10] == 0
    assert lines[11] == 1
    assert lines[12] == 1
    assert lines[13] == 1


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
