from pathlib import Path
import hashlib
import shutil
import struct
import subprocess
from types import SimpleNamespace

import pytest

from tests.journal_reader import decode_journal

from tests.trace_builder import (
    ETRACE_CONTEXT_F_INCOMPLETE,
    ETRACE_CONTEXT_F_PRIVILEGE_VALID,
    ETRACE_INFO_F_CONTEXT,
    ETRACE_INFO_F_FILTERED,
    ETRACE_INFO_F_FINAL_STATUS,
    ETRACE_TYPE_CONTEXT_GAP,
    ETRACE_TYPE_DISCONTINUITY,
    ETRACE_TYPE_TB_EXEC,
    etrace_arch,
    etrace_context,
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
    symbol_ranges = {}
    for line in symbols.stdout.splitlines():
        fields = line.split(maxsplit=3)
        if len(fields) == 4:
            symbol_ranges[fields[3]] = (int(fields[0], 16), int(fields[1], 16))
    if "x86_coverage_fixture" not in symbol_ranges:
        raise AssertionError("x86_coverage_fixture symbol not found")
    start, size = symbol_ranges["x86_coverage_fixture"]

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
        symbols=symbol_ranges,
        disassembly=disassembly.stdout.splitlines(),
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


def instruction_slice(fixture, first, last):
    start = fixture.instructions[first][0]
    end = fixture.instructions[last - 1][0] + fixture.instructions[last - 1][1]
    insns = tuple(
        (offset - start, size)
        for offset, size in fixture.instructions[first:last]
    )
    return start, end, insns, fixture.code[start:end]


def fallthrough_definition(fixture, tb_id, runtime, first, last, **kwargs):
    start, end, insns, code = instruction_slice(fixture, first, last)
    return etrace_tb_def(
        tb_id=tb_id, vaddr=runtime, insns=insns, code=code, **kwargs
    ), end - start


def fixture_function(fixture, name):
    start, size = fixture.symbols[name]
    instructions = []
    code = bytearray()
    for line in fixture.disassembly:
        fields = line.split("\t")
        if len(fields) < 3 or not fields[0].strip().endswith(":"):
            continue
        address = int(fields[0].strip()[:-1], 16)
        if start <= address < start + size:
            encoded = bytes.fromhex("".join(fields[1].split()))
            instructions.append((address - start, len(encoded)))
            code.extend(encoded)
    return SimpleNamespace(
        start=start, size=size, instructions=tuple(instructions), code=bytes(code)
    )


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


def test_etrace_v2_separates_count_and_duration(
    run_etrace, tmp_path, x86_fixture
):
    start = x86_fixture.start
    trace = tmp_path / "count-coverage.etrace"
    output = tmp_path / "count-coverage.txt"
    trace.write_bytes(
        etrace_arch(guest_bits=64)
        + etrace_exec64(duration=0, start=start + 1, end=start + 3)
        + etrace_exec64(duration=7, start=start + 0x100000, end=start + 0x100004)
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
        "etrace-v2",
        "--coverage-output",
        output,
    )
    assert result.returncode == 0, result.stderr

    lines = output.read_text(encoding="utf-8").splitlines()
    assert lines[:2] == [
        "# qemu-etrace coverage v2",
        "# count duration address symbol source",
    ]
    coverage = {
        int(fields[2], 16): (int(fields[0]), int(fields[1]))
        for line in lines[2:]
        if len(fields := line.split()) >= 4
        and fields[3] == "x86_coverage_fixture"
    }
    assert len(coverage) == 11
    assert coverage[start] == (0, 0)
    assert coverage[start + 1] == (1, 0)
    assert coverage[start + 2] == (1, 0)
    assert coverage[start + 3] == (0, 0)
    assert lines[-1] == "1 7 x unknown unknown:0"


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


@pytest.mark.parametrize(("selector", "expected_hit"), [
    ("x86_64:cpl0", 1),
    ("x86_64:cpl3", 0),
])
@pytest.mark.parametrize("ordered", [False, True])
def test_v1_elf_context_qualifies_coverage(
    run_etrace, tmp_path, x86_fixture, selector, expected_hit, ordered
):
    trace = tmp_path / f"elf-context-{selector.replace(':', '-')}.etrace"
    trace.write_bytes(
        etrace_info(major=1, attributes=ETRACE_INFO_F_CONTEXT)
        + etrace_context(
            context_id=3,
            pc=x86_fixture.start,
            architecture=62,
            privilege=0,
            flags=ETRACE_CONTEXT_F_PRIVILEGE_VALID,
        )
        + etrace_tb_def(
            tb_id=7,
            vaddr=x86_fixture.start,
            insns=tuple(x86_fixture.instructions),
            code=x86_fixture.code,
        )
        + etrace_tb_exec(
            tb_id=7,
            sequence=1,
            context_id=3,
            insn_count=len(x86_fixture.instructions),
        )
    )

    extra_args = ["--elf-context", selector]
    if ordered:
        extra_args += ["--auto-map", "--preserve-order"]
    result, (_, functions) = run_v1_lcov(
        run_etrace, tmp_path, x86_fixture, trace, *extra_args
    )

    assert result.returncode == 0, result.stderr
    assert functions["x86_coverage_fixture"] == expected_hit


def test_v1_elf_context_requires_trace_contexts(
    run_etrace, tmp_path, x86_fixture
):
    trace = tmp_path / "elf-context-missing.etrace"
    trace.write_bytes(
        etrace_info(major=1)
        + etrace_tb_def(
            tb_id=7,
            vaddr=x86_fixture.start,
            insns=tuple(x86_fixture.instructions),
        )
        + etrace_tb_exec(
            tb_id=7,
            sequence=1,
            insn_count=len(x86_fixture.instructions),
        )
    )

    result, _ = run_v1_lcov(
        run_etrace, tmp_path, x86_fixture, trace,
        "--elf-context", "x86_64:cpl0",
    )

    assert result.returncode != 0
    assert "requires trace context records" in result.stderr


def test_elf_context_requires_matching_elf_architecture(
    run_etrace, tmp_path, x86_fixture
):
    trace = tmp_path / "elf-context-architecture.etrace"
    trace.write_bytes(b"")

    result = run_etrace(
        "--trace",
        trace,
        "--trace-output",
        "none",
        "--elf",
        x86_fixture.binary,
        "--nm",
        x86_fixture.tools["nm"],
        "--elf-context",
        "aarch64:el2",
    )

    assert result.returncode != 0
    assert "architecture does not match the ELF" in result.stderr


@pytest.mark.parametrize("ordered", [False, True])
@pytest.mark.parametrize(("anchor_privilege", "expected_hit"), [(0, 2), (3, 0)])
def test_v1_elf_context_qualifies_mapping_anchor(
    run_etrace, tmp_path, x86_fixture, ordered, anchor_privilege, expected_hit
):
    physical = 0x200000
    trace = tmp_path / f"context-anchor-{ordered}-{anchor_privilege}.etrace"
    trace.write_bytes(
        etrace_info(major=1, attributes=ETRACE_INFO_F_CONTEXT)
        + etrace_context(
            context_id=1,
            pc=physical,
            architecture=62,
            privilege=0,
            flags=ETRACE_CONTEXT_F_PRIVILEGE_VALID,
        )
        + etrace_context(
            context_id=2,
            pc=x86_fixture.start,
            architecture=62,
            privilege=anchor_privilege,
            flags=ETRACE_CONTEXT_F_PRIVILEGE_VALID,
        )
        + etrace_tb_def(
            tb_id=1,
            vaddr=physical,
            insns=tuple(x86_fixture.instructions),
            mappings=((0, len(x86_fixture.code), physical),),
            code=x86_fixture.code,
        )
        + etrace_tb_exec(
            tb_id=1,
            sequence=1,
            context_id=1,
            insn_count=len(x86_fixture.instructions),
        )
        + etrace_tb_def(
            tb_id=2,
            vaddr=x86_fixture.start,
            insns=tuple(x86_fixture.instructions),
            mappings=((0, len(x86_fixture.code), physical),),
            code=x86_fixture.code,
        )
        + etrace_tb_exec(
            tb_id=2,
            sequence=2,
            context_id=2,
            insn_count=len(x86_fixture.instructions),
        )
    )
    extra_args = ["--auto-map", "--elf-context", "x86_64:cpl0"]
    if ordered:
        extra_args.append("--preserve-order")

    result, (_, functions) = run_v1_lcov(
        run_etrace, tmp_path, x86_fixture, trace, *extra_args
    )

    assert result.returncode == 0, result.stderr
    assert functions["x86_coverage_fixture"] == expected_hit


@pytest.mark.parametrize("ordered", [False, True])
def test_v1_context_anchor_maps_executable_load_segment(
    run_etrace, tmp_path, x86_fixture, ordered
):
    physical = 0x200000
    entry_instructions = tuple(x86_fixture.instructions[:3])
    entry_size = sum(size for _, size in entry_instructions)
    anchor_instructions = tuple(
        (offset - entry_size, size)
        for offset, size in x86_fixture.instructions[3:]
    )
    trace = tmp_path / f"context-image-mapping-{ordered}.etrace"
    trace.write_bytes(
        etrace_info(major=1, attributes=ETRACE_INFO_F_CONTEXT)
        + etrace_context(
            context_id=1,
            pc=physical,
            architecture=62,
            privilege=0,
            flags=ETRACE_CONTEXT_F_PRIVILEGE_VALID,
        )
        # Equal bytes outside the inferred image mapping remain untrusted.
        + etrace_tb_def(
            tb_id=1,
            vaddr=0x300000,
            insns=entry_instructions,
            mappings=((0, entry_size, 0x300000),),
            code=x86_fixture.code[:entry_size],
        )
        + etrace_tb_exec(
            tb_id=1,
            sequence=1,
            context_id=1,
            insn_count=len(entry_instructions),
        )
        # The short physical entry executes before the linked anchor.
        + etrace_tb_def(
            tb_id=2,
            vaddr=physical,
            insns=entry_instructions,
            mappings=((0, entry_size, physical),),
            code=x86_fixture.code[:entry_size],
        )
        + etrace_tb_exec(
            tb_id=2,
            sequence=2,
            context_id=1,
            insn_count=len(entry_instructions),
        )
        + etrace_tb_def(
            tb_id=3,
            vaddr=x86_fixture.start + entry_size,
            insns=anchor_instructions,
            mappings=((0, len(x86_fixture.code) - entry_size,
                       physical + entry_size),),
            code=x86_fixture.code[entry_size:],
        )
        + etrace_tb_exec(
            tb_id=3,
            sequence=3,
            context_id=1,
            insn_count=len(anchor_instructions),
        )
    )
    extra_args = ["--auto-map", "--elf-context", "x86_64:cpl0"]
    if ordered:
        extra_args.append("--preserve-order")

    result, (_, functions) = run_v1_lcov(
        run_etrace, tmp_path, x86_fixture, trace, *extra_args
    )

    assert result.returncode == 0, result.stderr
    assert functions["x86_coverage_fixture"] == 1
    assert "context-qualified executable image mapping" in result.stderr
    if ordered:
        assert "retained 1 unresolved execution boundaries" in result.stderr
    else:
        assert "1 execution events in 1 unresolved aggregates" in result.stderr


@pytest.mark.parametrize("ordered", [False, True])
def test_v1_context_anchor_recovers_incomplete_early_context(
    run_etrace, tmp_path, x86_fixture, ordered
):
    physical = 0x200000
    entry_instructions = tuple(x86_fixture.instructions[:3])
    entry_size = sum(size for _, size in entry_instructions)
    anchor_instructions = tuple(
        (offset - entry_size, size)
        for offset, size in x86_fixture.instructions[3:]
    )
    trace = tmp_path / f"incomplete-context-{ordered}.etrace"
    trace.write_bytes(
        etrace_info(major=1, attributes=ETRACE_INFO_F_CONTEXT)
        + etrace_context(
            context_id=1,
            pc=physical,
            architecture=62,
            flags=ETRACE_CONTEXT_F_INCOMPLETE,
        )
        + etrace_context(
            context_id=2,
            pc=x86_fixture.start + entry_size,
            architecture=62,
            privilege=0,
            flags=ETRACE_CONTEXT_F_PRIVILEGE_VALID,
        )
        + etrace_tb_def(
            tb_id=3,
            vaddr=0x300000,
            insns=entry_instructions,
            mappings=((0, entry_size, 0x300000),),
            code=x86_fixture.code[:entry_size],
        )
        + etrace_tb_exec(
            tb_id=3, sequence=1, context_id=1,
            insn_count=len(entry_instructions),
        )
        + etrace_tb_def(
            tb_id=1,
            vaddr=physical,
            insns=entry_instructions,
            mappings=((0, entry_size, physical),),
            code=x86_fixture.code[:entry_size],
        )
        + etrace_tb_exec(
            tb_id=1, sequence=2, context_id=1,
            insn_count=len(entry_instructions),
        )
        + etrace_tb_def(
            tb_id=2,
            vaddr=x86_fixture.start + entry_size,
            insns=anchor_instructions,
            mappings=((0, len(x86_fixture.code) - entry_size,
                       physical + entry_size),),
            code=x86_fixture.code[entry_size:],
        )
        + etrace_tb_exec(
            tb_id=2, sequence=3, context_id=2,
            insn_count=len(anchor_instructions),
        )
    )
    extra_args = ["--auto-map", "--elf-context", "x86_64:cpl0"]
    if ordered:
        extra_args.append("--preserve-order")

    result, (_, functions) = run_v1_lcov(
        run_etrace, tmp_path, x86_fixture, trace, *extra_args
    )

    assert result.returncode == 0, result.stderr
    assert functions["x86_coverage_fixture"] == 1
    if ordered:
        assert "retained 1 unresolved execution boundaries" in result.stderr
    else:
        assert "1 execution events in 1 unresolved aggregates" in result.stderr


@pytest.mark.parametrize("ordered", [False, True])
def test_v1_owned_mapping_credits_matching_instruction_prefix(
    run_etrace, tmp_path, x86_fixture, ordered
):
    physical = 0x200000
    changed = x86_fixture.code[:-1] + b"\xcc"
    anchor_offset, anchor_size = x86_fixture.instructions[1]
    trace = tmp_path / f"partial-owned-{ordered}.etrace"
    trace.write_bytes(
        etrace_info(major=1, attributes=ETRACE_INFO_F_CONTEXT)
        + etrace_context(
            context_id=1,
            pc=physical,
            architecture=62,
            privilege=0,
            flags=ETRACE_CONTEXT_F_PRIVILEGE_VALID,
        )
        + etrace_tb_def(
            tb_id=1,
            vaddr=physical,
            insns=tuple(x86_fixture.instructions),
            mappings=((0, len(changed), physical),),
            code=changed,
        )
        + etrace_tb_exec(
            tb_id=1, sequence=1, context_id=1,
            insn_count=len(x86_fixture.instructions),
        )
        + etrace_tb_def(
            tb_id=2,
            vaddr=x86_fixture.start + anchor_offset,
            insns=((0, anchor_size),),
            mappings=((0, anchor_size, physical + anchor_offset),),
            code=x86_fixture.code[anchor_offset:anchor_offset + anchor_size],
        )
        + etrace_tb_exec(
            tb_id=2, sequence=2, context_id=1, insn_count=1,
        )
    )
    extra_args = ["--auto-map", "--elf-context", "x86_64:cpl0"]
    if ordered:
        extra_args.append("--preserve-order")

    result, (lines, functions) = run_v1_lcov(
        run_etrace, tmp_path, x86_fixture, trace, *extra_args
    )

    assert result.returncode == 0, result.stderr
    assert functions["x86_coverage_fixture"] == 1
    assert lines[10] == lines[12] == lines[13] == lines[14] == 1
    assert lines[11] == 2
    assert lines[15] == 0
    assert "1 partially verified execution events" in result.stderr
    if ordered:
        assert "retained 1 unresolved execution boundaries" in result.stderr


@pytest.mark.parametrize("ordered", [False, True])
def test_v1_partial_match_does_not_establish_mapping(
    run_etrace, tmp_path, x86_fixture, ordered
):
    physical = 0x200000
    changed = x86_fixture.code[:-1] + b"\xcc"
    trace = tmp_path / f"partial-unowned-{ordered}.etrace"
    trace.write_bytes(
        etrace_info(major=1, attributes=ETRACE_INFO_F_CONTEXT)
        + etrace_context(
            context_id=1,
            pc=x86_fixture.start,
            architecture=62,
            privilege=0,
            flags=ETRACE_CONTEXT_F_PRIVILEGE_VALID,
        )
        + etrace_tb_def(
            tb_id=1,
            vaddr=x86_fixture.start,
            insns=tuple(x86_fixture.instructions),
            mappings=((0, len(changed), physical),),
            code=changed,
        )
        + etrace_tb_exec(
            tb_id=1, sequence=1, context_id=1,
            insn_count=len(x86_fixture.instructions),
        )
    )
    extra_args = ["--auto-map", "--elf-context", "x86_64:cpl0"]
    if ordered:
        extra_args.append("--preserve-order")

    result, (_, functions) = run_v1_lcov(
        run_etrace, tmp_path, x86_fixture, trace, *extra_args
    )

    assert result.returncode == 0, result.stderr
    assert functions["x86_coverage_fixture"] == 0
    assert "partially verified" not in result.stderr


def test_v1_context_anchor_releases_ordered_journal(
    run_etrace, tmp_path, x86_fixture
):
    physical = 0x200000
    entry_instructions = tuple(x86_fixture.instructions[:3])
    entry_size = sum(size for _, size in entry_instructions)
    anchor_instructions = tuple(
        (offset - entry_size, size)
        for offset, size in x86_fixture.instructions[3:]
    )
    trace = tmp_path / "ordered-prefix.etrace"
    spool = tmp_path / "ordered-prefix.journal"
    packets = [
        etrace_info(major=1, attributes=ETRACE_INFO_F_CONTEXT),
        etrace_context(
            context_id=1,
            pc=physical,
            architecture=62,
            privilege=0,
            flags=ETRACE_CONTEXT_F_PRIVILEGE_VALID,
        ),
        etrace_tb_def(
            tb_id=1,
            vaddr=physical,
            insns=entry_instructions,
            mappings=((0, entry_size, physical),),
            code=x86_fixture.code[:entry_size],
        ),
        etrace_tb_exec(
            tb_id=1, sequence=1, context_id=1,
            insn_count=len(entry_instructions),
        ),
        etrace_tb_def(
            tb_id=2,
            vaddr=x86_fixture.start + entry_size,
            insns=anchor_instructions,
            mappings=((0, len(x86_fixture.code) - entry_size,
                       physical + entry_size),),
            code=x86_fixture.code[entry_size:],
        ),
        etrace_tb_exec(
            tb_id=2, sequence=2, context_id=1,
            insn_count=len(anchor_instructions),
        ),
    ]
    packets.extend(
        etrace_tb_exec(
            tb_id=1, sequence=sequence, context_id=1,
            insn_count=len(entry_instructions),
        )
        for sequence in range(3, 203)
    )
    trace.write_bytes(b"".join(packets))

    result, (_, functions) = run_v1_lcov(
        run_etrace,
        tmp_path,
        x86_fixture,
        trace,
        "--auto-map",
        "--elf-context",
        "x86_64:cpl0",
        "--preserve-order",
        "--event-spool",
        spool,
        "--event-spool-decoded-limit",
        "96",
    )

    assert result.returncode == 0, result.stderr
    assert functions["x86_coverage_fixture"] == 201
    assert "switched to online processing" in result.stderr
    journal = decode_journal(spool.read_bytes())
    assert len(journal) == 96
    assert [
        struct.unpack_from("=H", journal, offset)[0]
        for offset in range(0, len(journal), 48)
    ] == [ETRACE_TYPE_TB_EXEC, ETRACE_TYPE_TB_EXEC]

    copied = tmp_path / "ordered-prefix-copy.etrace"
    copied_spool = tmp_path / "ordered-prefix-copy.journal"
    passthrough = run_etrace(
        "--trace",
        trace,
        "--trace-in-format",
        "etrace",
        "--trace-out-format",
        "etrace",
        "--trace-output",
        copied,
        "--elf",
        x86_fixture.binary,
        "--nm",
        x86_fixture.tools["nm"],
        "--auto-map",
        "--elf-context",
        "x86_64:cpl0",
        "--preserve-order",
        "--event-spool",
        copied_spool,
        "--event-spool-decoded-limit",
        "96",
    )
    assert passthrough.returncode == 0, passthrough.stderr
    assert copied.read_bytes() == trace.read_bytes()


def test_v1_complete_explicit_map_skips_ordered_journal(
    run_etrace, tmp_path, x86_fixture
):
    linked_base = x86_fixture.start & ~0xFFFF
    physical_base = 0x200000
    physical = physical_base + x86_fixture.start - linked_base
    trace = tmp_path / "ordered-explicit-map.etrace"
    spool = tmp_path / "ordered-explicit-map.journal"
    packets = [
        etrace_info(major=1),
        etrace_tb_def(
            tb_id=1,
            vaddr=physical,
            insns=tuple(x86_fixture.instructions),
            mappings=((0, len(x86_fixture.code), physical),),
            code=x86_fixture.code,
        ),
    ]
    packets.extend(
        etrace_tb_exec(
            tb_id=1, sequence=sequence,
            insn_count=len(x86_fixture.instructions),
        )
        for sequence in range(1, 101)
    )
    trace.write_bytes(b"".join(packets))

    result, (_, functions) = run_v1_lcov(
        run_etrace,
        tmp_path,
        x86_fixture,
        trace,
        "--auto-map",
        "--address-map",
        f"{physical_base:x}:{linked_base:x}:10000",
        "--preserve-order",
        "--event-spool",
        spool,
        "--event-spool-decoded-limit",
        "1",
    )

    assert result.returncode == 0, result.stderr
    assert functions["x86_coverage_fixture"] == 100
    assert "switched to online processing" in result.stderr
    assert decode_journal(spool.read_bytes()) == b""


@pytest.mark.parametrize("physical", [0x200000, 0x200FFC, 0xFFFFFFFFFFFFF000])
def test_v1_auto_map_replays_early_physical_execution(
    run_etrace, tmp_path, x86_fixture, physical
):
    linked = x86_fixture.start
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


@pytest.mark.parametrize("physical_mappings", [False, True])
def test_v1_auto_map_propagates_exact_fallthrough(
    run_etrace, tmp_path, x86_fixture, physical_mappings
):
    linked = x86_fixture.start
    runtime = 0x30000000
    first, first_len = fallthrough_definition(
        x86_fixture, 1, runtime, 0, 2, context_id=1
    )
    second, second_len = fallthrough_definition(
        x86_fixture, 2, runtime + first_len, 2, 4, context_id=1,
        mappings=((0, 5, 0x800003),) if physical_mappings else (),
    )
    third, _ = fallthrough_definition(
        x86_fixture, 3, runtime + first_len + second_len, 4, 6,
        context_id=1,
        mappings=((0, 3, 0x800008),) if physical_mappings else (),
    )
    trace = tmp_path / "fallthrough.etrace"
    trace.write_bytes(
        etrace_info(major=1, attributes=ETRACE_INFO_F_CONTEXT)
        + etrace_context(
            context_id=1, architecture=62, privilege=0,
            flags=ETRACE_CONTEXT_F_PRIVILEGE_VALID,
        )
        + first
        + etrace_tb_exec(tb_id=1, sequence=1, context_id=1, insn_count=2)
        + second
        + etrace_tb_exec(tb_id=2, sequence=2, context_id=1, insn_count=2)
        + third
        + etrace_tb_exec(tb_id=3, sequence=3, context_id=1, insn_count=2)
    )
    result, (lines, functions) = run_v1_lcov(
        run_etrace, tmp_path, x86_fixture, trace,
        "--auto-map", "--elf-context", "x86_64:cpl0",
        "--address-map", f"{runtime:x}:{linked:x}:{first_len:x}",
        "--preserve-order",
    )

    assert result.returncode == 0, result.stderr
    assert functions["x86_coverage_fixture"] == 1
    assert all(lines[line] == 1 for line in range(10, 16))
    assert "resolved 2 translation blocks by exact fallthrough" in result.stderr
    assert "unresolved" not in result.stderr


def test_v1_fallthrough_mapping_remains_context_local(
    run_etrace, tmp_path, x86_fixture
):
    linked = x86_fixture.start
    runtime = 0x30500000
    first, first_len = fallthrough_definition(
        x86_fixture, 1, runtime, 0, 2, context_id=1
    )
    second, _ = fallthrough_definition(
        x86_fixture, 2, runtime + first_len, 2, 4, context_id=1
    )
    trace = tmp_path / "fallthrough-context-local.etrace"
    trace.write_bytes(
        etrace_info(major=1, attributes=ETRACE_INFO_F_CONTEXT)
        + etrace_context(
            context_id=1, architecture=62, privilege=0,
            flags=ETRACE_CONTEXT_F_PRIVILEGE_VALID,
        )
        + etrace_context(
            context_id=2, architecture=62, privilege=0,
            flags=ETRACE_CONTEXT_F_PRIVILEGE_VALID,
        )
        + first
        + etrace_tb_exec(tb_id=1, sequence=1, context_id=1, insn_count=2)
        + second
        + etrace_tb_exec(tb_id=2, sequence=2, context_id=1, insn_count=2)
        + etrace_tb_exec(tb_id=2, sequence=3, context_id=2, insn_count=2)
    )
    result, (lines, _) = run_v1_lcov(
        run_etrace, tmp_path, x86_fixture, trace,
        "--auto-map", "--elf-context", "x86_64:cpl0",
        "--address-map", f"{runtime:x}:{linked:x}:{first_len:x}",
        "--preserve-order",
    )

    assert result.returncode == 0, result.stderr
    assert lines[12] == 1
    assert "1 unresolved" in result.stderr


@pytest.mark.parametrize(
    ("second_proof", "expected_count"),
    [
        ("same-context-vcpu", 2),
        ("no-predecessor", 1),
        ("context-change", 1),
        ("vcpu-change", 1),
    ],
)
def test_v1_fallthrough_mapping_requires_per_context_proof(
    run_etrace, tmp_path, x86_fixture, second_proof, expected_count
):
    linked = x86_fixture.start
    runtime = 0x30800000
    anchor, anchor_len = fallthrough_definition(
        x86_fixture, 1, runtime, 0, 2, context_id=1
    )
    successor, _ = fallthrough_definition(
        x86_fixture, 2, runtime + anchor_len, 2, 4, context_id=1
    )
    packets = [
        etrace_info(major=1, attributes=ETRACE_INFO_F_CONTEXT),
        etrace_context(
            context_id=1, architecture=62, privilege=0,
            flags=ETRACE_CONTEXT_F_PRIVILEGE_VALID,
        ),
        etrace_context(
            context_id=2, architecture=62, privilege=0,
            flags=ETRACE_CONTEXT_F_PRIVILEGE_VALID,
        ),
        anchor,
        successor,
        etrace_tb_exec(
            tb_id=1, sequence=1, context_id=1, insn_count=2,
        ),
        etrace_tb_exec(
            tb_id=2, sequence=2, context_id=1, insn_count=2,
        ),
    ]
    if second_proof == "same-context-vcpu":
        packets.append(etrace_tb_exec(
            tb_id=1, sequence=1, context_id=2, insn_count=2, unit_id=1,
        ))
        successor_unit = 1
        successor_sequence = 2
    elif second_proof == "no-predecessor":
        successor_unit = 1
        successor_sequence = 1
    elif second_proof == "context-change":
        packets.append(etrace_tb_exec(
            tb_id=1, sequence=1, context_id=1, insn_count=2, unit_id=1,
        ))
        successor_unit = 1
        successor_sequence = 2
    else:
        packets.append(etrace_tb_exec(
            tb_id=1, sequence=1, context_id=2, insn_count=2, unit_id=1,
        ))
        successor_unit = 2
        successor_sequence = 1
    packets.append(etrace_tb_exec(
        tb_id=2, sequence=successor_sequence, context_id=2,
        insn_count=2, unit_id=successor_unit,
    ))
    trace = tmp_path / f"fallthrough-shared-{second_proof}.etrace"
    trace.write_bytes(b"".join(packets))

    result, (lines, _) = run_v1_lcov(
        run_etrace, tmp_path, x86_fixture, trace,
        "--auto-map", "--elf-context", "x86_64:cpl0",
        "--address-map", f"{runtime:x}:{linked:x}:{anchor_len:x}",
        "--preserve-order",
    )

    assert result.returncode == 0, result.stderr
    assert lines[12] == lines[13] == expected_count
    assert "resolved 1 translation block by exact fallthrough" in result.stderr
    assert ("retained 1 unresolved execution boundaries" in result.stderr) == (
        expected_count == 1
    )


@pytest.mark.parametrize(
    "boundary",
    [
        "discontinuity-unknown",
        "discontinuity-interrupt",
        "discontinuity-exception",
        "discontinuity-host-call",
        "context-gap",
        "context-change",
        "different-vcpu",
        "partial-dispatch",
        "runtime-gap",
        "runtime-page",
        "linked-gap",
        "wrong-bytes",
        "explicit-overlap",
    ],
)
def test_v1_auto_map_fallthrough_boundaries_fail_closed(
    run_etrace, tmp_path, x86_fixture, boundary
):
    linked = x86_fixture.start
    runtime = 0x31000FFD if boundary == "runtime-page" else 0x31000000
    anchor_last = 3 if boundary == "partial-dispatch" else 2
    successor_first = 3 if boundary in ("partial-dispatch", "linked-gap") else 2
    first, first_len = fallthrough_definition(
        x86_fixture, 1, runtime, 0, anchor_last, context_id=1
    )
    successor_runtime = runtime + first_len
    if boundary == "runtime-gap":
        successor_runtime += 1
    successor_start, successor_end, successor_insns, successor_code = (
        instruction_slice(x86_fixture, successor_first, successor_first + 1)
    )
    if boundary == "wrong-bytes":
        successor_code = bytes([successor_code[0] ^ 1]) + successor_code[1:]
    second = etrace_tb_def(
        tb_id=2, vaddr=successor_runtime,
        context_id=2 if boundary == "context-change" else 1,
        insns=successor_insns, code=successor_code,
    )
    second_len = successor_end - successor_start
    attributes = ETRACE_INFO_F_CONTEXT
    if boundary == "context-gap":
        attributes |= ETRACE_INFO_F_FILTERED
    packets = [
        etrace_info(major=1, attributes=attributes),
        etrace_context(
            context_id=1, architecture=62, privilege=0,
            flags=ETRACE_CONTEXT_F_PRIVILEGE_VALID,
        ),
        etrace_context(
            context_id=2, architecture=62, privilege=0,
            flags=ETRACE_CONTEXT_F_PRIVILEGE_VALID,
        ),
        first,
        etrace_tb_exec(
            tb_id=1, sequence=1, context_id=1,
            insn_count=2 if boundary == "partial-dispatch" else anchor_last,
        ),
    ]
    sequence = 2
    if boundary.startswith("discontinuity-"):
        kind = {
            "discontinuity-unknown": 0,
            "discontinuity-interrupt": 1,
            "discontinuity-exception": 2,
            "discontinuity-host-call": 3,
        }[boundary]
        packets.append(etrace_discontinuity(
            from_pc=runtime + first_len, to_pc=successor_runtime,
            kind=kind,
        ))
    elif boundary == "context-gap":
        packets.append(etrace_context_gap(
            sequence=2, from_context_id=1, to_context_id=1,
        ))
        sequence = 3
    packets += [
        second,
        etrace_tb_exec(
            tb_id=2, sequence=1 if boundary == "different-vcpu" else sequence,
            context_id=2 if boundary == "context-change" else 1,
            insn_count=1,
            unit_id=1 if boundary == "different-vcpu" else 0,
        ),
    ]
    trace = tmp_path / f"fallthrough-{boundary}.etrace"
    trace.write_bytes(b"".join(packets))
    extra = []
    if boundary == "explicit-overlap":
        extra = [
            "--address-map",
            f"{successor_runtime + 1:x}:{linked + first_len + 1:x}:1",
        ]
    result, (lines, functions) = run_v1_lcov(
        run_etrace, tmp_path, x86_fixture, trace,
        "--auto-map", "--elf-context", "x86_64:cpl0",
        "--address-map", f"{runtime:x}:{linked:x}:{first_len:x}",
        "--preserve-order", *extra,
    )

    assert result.returncode == 0, result.stderr
    assert functions["x86_coverage_fixture"] == 1
    assert lines[12] == 0
    assert "by exact fallthrough" not in result.stderr
    assert "retained 1 unresolved execution boundaries" in result.stderr


def test_v1_auto_map_does_not_propagate_after_nonfallthrough_branch(
    run_etrace, tmp_path, x86_fixture
):
    linked = x86_fixture.start
    runtime = 0x32000000
    repeated = x86_fixture.code[:3]
    trace = tmp_path / "fallthrough-return.etrace"
    trace.write_bytes(
        etrace_info(major=1, attributes=ETRACE_INFO_F_CONTEXT)
        + etrace_context(
            context_id=1, architecture=62, privilege=0,
            flags=ETRACE_CONTEXT_F_PRIVILEGE_VALID,
        )
        + etrace_tb_def(
            tb_id=1, vaddr=runtime, context_id=1,
            insns=((0, 1),), code=b"\xc3",
        )
        + etrace_tb_exec(
            tb_id=1, sequence=1, context_id=1, insn_count=1,
        )
        + etrace_tb_def(
            tb_id=2, vaddr=runtime + 1, context_id=1,
            insns=((0, 1), (1, 2)), code=repeated,
        )
        + etrace_tb_exec(
            tb_id=2, sequence=2, context_id=1, insn_count=2,
        )
    )
    result, _ = run_v1_lcov(
        run_etrace, tmp_path, x86_fixture, trace,
        "--auto-map",
        "--address-map", f"{runtime:x}:{linked + 10:x}:1",
        "--preserve-order",
    )

    assert result.returncode == 0, result.stderr
    assert "by exact fallthrough" not in result.stderr
    assert "unresolved" in result.stderr


@pytest.mark.parametrize(
    "name",
    [
        "fallthrough_call_fixture",
        "fallthrough_jump_fixture",
        "fallthrough_conditional_fixture",
        "fallthrough_trap_fixture",
        "fallthrough_undecodable_fixture",
    ],
)
def test_v1_auto_map_rejects_nonordinary_predecessors(
    run_etrace, tmp_path, x86_fixture, name
):
    function = fixture_function(x86_fixture, name)
    runtime = 0x32300000
    trace = tmp_path / f"fallthrough-{name}.etrace"
    trace.write_bytes(
        etrace_info(major=1, attributes=ETRACE_INFO_F_CONTEXT)
        + etrace_context(
            context_id=1, architecture=62, privilege=0,
            flags=ETRACE_CONTEXT_F_PRIVILEGE_VALID,
        )
        + etrace_tb_def(
            tb_id=1, vaddr=runtime, context_id=1,
            insns=function.instructions, code=function.code,
        )
        + etrace_tb_exec(
            tb_id=1, sequence=1, context_id=1,
            insn_count=len(function.instructions),
        )
        + etrace_tb_def(
            tb_id=2, vaddr=runtime + function.size, context_id=1,
            insns=((0, 1),), code=b"\xc3",
        )
        + etrace_tb_exec(
            tb_id=2, sequence=2, context_id=1, insn_count=1,
        )
    )

    result, _ = run_v1_lcov(
        run_etrace, tmp_path, x86_fixture, trace,
        "--auto-map", "--preserve-order",
        "--address-map",
        f"{runtime:x}:{function.start:x}:{function.size:x}",
    )

    assert result.returncode == 0, result.stderr
    assert "by exact fallthrough" not in result.stderr
    assert "retained 1 unresolved execution boundaries" in result.stderr


def test_v1_auto_map_does_not_propagate_unordered_fallthrough(
    run_etrace, tmp_path, x86_fixture
):
    linked = x86_fixture.start
    runtime = 0x32500000
    first, first_len = fallthrough_definition(
        x86_fixture, 1, runtime, 0, 2
    )
    second, _ = fallthrough_definition(
        x86_fixture, 2, runtime + first_len, 2, 4
    )
    trace = tmp_path / "fallthrough-unordered.etrace"
    trace.write_bytes(
        etrace_info(major=1)
        + first
        + etrace_tb_exec(tb_id=1, sequence=1, insn_count=2)
        + second
        + etrace_tb_exec(tb_id=2, sequence=2, insn_count=2)
    )

    result, (lines, functions) = run_v1_lcov(
        run_etrace, tmp_path, x86_fixture, trace,
        "--auto-map",
        "--address-map", f"{runtime:x}:{linked:x}:{first_len:x}",
    )

    assert result.returncode == 0, result.stderr
    assert functions["x86_coverage_fixture"] == 1
    assert lines[12] == 0
    assert "by exact fallthrough" not in result.stderr
    assert "1 execution events in 1 unresolved aggregates" in result.stderr


def test_v1_auto_map_fallthrough_requires_nonzero_context(
    run_etrace, tmp_path, x86_fixture
):
    linked = x86_fixture.start
    runtime = 0x32600000
    first, first_len = fallthrough_definition(
        x86_fixture, 1, runtime, 0, 2
    )
    second, _ = fallthrough_definition(
        x86_fixture, 2, runtime + first_len, 2, 4
    )
    trace = tmp_path / "fallthrough-zero-context.etrace"
    trace.write_bytes(
        etrace_info(major=1)
        + first
        + etrace_tb_exec(tb_id=1, sequence=1, insn_count=2)
        + second
        + etrace_tb_exec(tb_id=2, sequence=2, insn_count=2)
    )

    result, (lines, functions) = run_v1_lcov(
        run_etrace, tmp_path, x86_fixture, trace,
        "--auto-map", "--preserve-order",
        "--address-map", f"{runtime:x}:{linked:x}:{first_len:x}",
    )

    assert result.returncode == 0, result.stderr
    assert functions["x86_coverage_fixture"] == 1
    assert lines[12] == 0
    assert "by exact fallthrough" not in result.stderr
    assert "retained 1 unresolved execution boundaries" in result.stderr


def test_v1_fallthrough_mapping_rejects_physical_conflict(
    run_etrace, tmp_path, x86_fixture
):
    linked = x86_fixture.start
    runtime = 0x32800000
    anchor, anchor_len = fallthrough_definition(
        x86_fixture, 1, runtime, 0, 2
    )
    successor, _ = fallthrough_definition(
        x86_fixture, 2, runtime + anchor_len, 2, 4,
        mappings=((0, 5, 0x900000),),
    )
    other_start, other_end, other_insns, other_code = instruction_slice(
        x86_fixture, 3, 6
    )
    trace = tmp_path / "fallthrough-physical-conflict.etrace"
    trace.write_bytes(
        etrace_info(major=1, attributes=ETRACE_INFO_F_CONTEXT)
        + etrace_context(
            context_id=1, architecture=62, privilege=0,
            flags=ETRACE_CONTEXT_F_PRIVILEGE_VALID,
        )
        + etrace_tb_def(
            tb_id=3, vaddr=linked + other_start,
            context_id=1,
            insns=other_insns, mappings=((0, other_end - other_start,
                                          0x900000),),
            code=other_code,
        )
        + etrace_tb_exec(
            tb_id=3, sequence=1, context_id=1,
            insn_count=len(other_insns), unit_id=1,
        )
        + anchor
        + etrace_tb_exec(tb_id=1, sequence=1, context_id=1, insn_count=2)
        + successor
        + etrace_tb_exec(tb_id=2, sequence=2, context_id=1, insn_count=2)
    )

    result, _ = run_v1_lcov(
        run_etrace, tmp_path, x86_fixture, trace,
        "--auto-map",
        "--address-map", f"{runtime:x}:{linked:x}:{anchor_len:x}",
        "--preserve-order",
    )

    assert result.returncode != 0
    assert "conflicting physical image mappings" in result.stderr
    assert not trace.with_suffix(".info").exists()


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


@pytest.mark.parametrize("ordered", [False, True])
@pytest.mark.parametrize("reverse", [False, True])
def test_v1_auto_map_rejects_conflicting_physical_claims(
    run_etrace, tmp_path, x86_fixture, ordered, reverse
):
    # The fixture repeats its first eight bytes immediately after the function.
    addresses = [x86_fixture.start, x86_fixture.start + len(x86_fixture.code)]
    if reverse:
        addresses.reverse()
    packets = [etrace_info(major=1)]
    for number, linked in enumerate(addresses, 1):
        packets.extend([
            etrace_tb_def(
                tb_id=number, vaddr=linked, insns=tuple(x86_fixture.instructions[:4]),
                mappings=((0, 8, 0x200000),), code=x86_fixture.code[:8],
            ),
            etrace_tb_exec(tb_id=number, sequence=number, insn_count=4),
        ])
    trace = tmp_path / "conflicting-physical-claims.etrace"
    trace.write_bytes(b"".join(packets))
    extra = ("--preserve-order",) if ordered else ()
    result, _ = run_v1_lcov(
        run_etrace, tmp_path, x86_fixture, trace, "--auto-map", *extra
    )
    assert result.returncode != 0
    assert "conflicting physical image mappings" in result.stderr
    assert not trace.with_suffix(".info").exists()


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
    data = decode_journal(spool.read_bytes())
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


def test_v1_journal_preserves_record_bytes_and_coverage(
    run_etrace, tmp_path, x86_fixture
):
    sequences = [0, 0]
    events = []
    gap_count = 0
    for number in range(10000):
        cpu = number % 2
        sequences[cpu] += 1
        events.append(etrace_tb_exec(
            sequence=sequences[cpu], time=number * 7, duration=number % 19,
            insn_count=1 + number % len(x86_fixture.instructions), unit_id=cpu,
            extension=b"\xa5" * (number % 11),
        ))
        if number % 97 == 0:
            sequences[cpu] += 1
            gap_count += 1
            events.append(etrace_context_gap(
                sequence=sequences[cpu], filtered_execs=1, unit_id=cpu,
            ))
            events.append(etrace_discontinuity(
                from_pc=x86_fixture.start, to_pc=x86_fixture.start + 8,
                kind=1, unit_id=cpu,
            ))
    logical = b"".join(events)
    trace = tmp_path / "journal-roundtrip.etrace"
    trace.write_bytes(
        etrace_info(
            major=1,
            attributes=ETRACE_INFO_F_FILTERED | ETRACE_INFO_F_FINAL_STATUS,
        )
        + etrace_tb_def(
            vaddr=x86_fixture.start, insns=tuple(x86_fixture.instructions),
            code=x86_fixture.code,
        )
        + logical
        + etrace_status_v1(filtered_execs=gap_count)
    )
    reference, expected = run_v1_lcov(
        run_etrace, tmp_path, x86_fixture, trace, "--auto-map"
    )
    assert reference.returncode == 0, reference.stderr
    spool = tmp_path / "journal-roundtrip.bin"
    result, actual = run_v1_lcov(
        run_etrace, tmp_path, x86_fixture, trace, "--auto-map",
        "--preserve-order", "--event-spool", spool,
        "--event-spool-decoded-limit", len(logical),
    )
    assert result.returncode == 0, result.stderr
    assert actual == expected
    assert decode_journal(spool.read_bytes()) == logical
    assert spool.stat().st_size < len(logical) / 2
    assert f"sha256={hashlib.sha256(logical).hexdigest()}" in result.stderr
    assert f"logical={len(logical)} stored={spool.stat().st_size}" in result.stderr
    assert f"tb-exec=10000 context-gap={gap_count} discontinuity={gap_count}" in result.stderr

    # Encoding and its storage footprint are independent of the configured cap.
    exact = spool.stat().st_size
    for limit, succeeds in ((exact, True), (exact - 1, False)):
        output = tmp_path / f"bounded-{limit}.info"
        checked = run_etrace(
            "--trace", trace, "--trace-output", "none", "--elf", x86_fixture.binary,
            "--auto-map", "--preserve-order", "--event-spool", spool,
            "--event-spool-limit", limit, "--coverage-format", "lcov",
            "--coverage-output", output,
        )
        assert (checked.returncode == 0) == succeeds, checked.stderr
        assert output.exists() == succeeds
        assert spool.stat().st_size <= limit
        if succeeds:
            assert decode_journal(spool.read_bytes()) == logical
        else:
            assert "event spool limit exceeded" in checked.stderr

    output = tmp_path / "decoded-limit.info"
    checked = run_etrace(
        "--trace", trace, "--trace-output", "none", "--elf", x86_fixture.binary,
        "--auto-map", "--preserve-order", "--event-spool-decoded-limit",
        len(logical) - 1, "--coverage-format", "lcov", "--coverage-output", output,
    )
    assert checked.returncode != 0
    assert "event spool decoded limit exceeded" in checked.stderr
    assert not output.exists()


@pytest.mark.parametrize("status", [b"", etrace_status_v1(code_errors=1)])
def test_v1_journal_requires_successful_producer_status(
    run_etrace, tmp_path, x86_fixture, status
):
    trace = tmp_path / "invalid-journal-status.etrace"
    trace.write_bytes(
        etrace_info(major=1, attributes=ETRACE_INFO_F_FINAL_STATUS)
        + etrace_tb_def(vaddr=x86_fixture.start, code=x86_fixture.code[:1], insns=((0, 1),))
        + etrace_tb_exec() + status
    )
    output = tmp_path / "invalid-journal-status.info"
    result = run_etrace(
        "--trace", trace, "--trace-output", "none", "--elf", x86_fixture.binary,
        "--auto-map", "--preserve-order", "--coverage-format", "lcov",
        "--coverage-output", output,
    )
    assert result.returncode != 0
    assert "producer" in result.stderr
    assert "replay-complete" not in result.stderr
    assert not output.exists()


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
