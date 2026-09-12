from pathlib import Path
import shutil
import struct
import subprocess
from types import SimpleNamespace

import pytest

from tests.trace_builder import etrace_info, etrace_tb_def, etrace_tb_exec


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "tests/fixtures/x86-alt-call.s"


def find_x86_tool(name):
    return shutil.which(f"x86_64-linux-gnu-{name}") or shutil.which(name)


@pytest.fixture(scope="module")
def alt_call_fixture(tmp_path_factory):
    tools = {
        "cc": find_x86_tool("gcc"),
        "nm": find_x86_tool("nm"),
        "objdump": find_x86_tool("objdump"),
        "dwarfdump": shutil.which("dwarfdump"),
    }
    missing = [name for name, path in tools.items() if path is None]
    if missing:
        pytest.skip(f"x86 alternative-call fixture requires: {', '.join(missing)}")
    target = subprocess.run(
        [tools["cc"], "-dumpmachine"], text=True, capture_output=True, check=True
    ).stdout.strip()
    if not target.startswith("x86_64"):
        pytest.skip("x86 alternative-call fixture requires an x86-64 compiler")

    binary = tmp_path_factory.mktemp("x86-alt-call") / "fixture"
    subprocess.run(
        [
            tools["cc"], "-g", "-nostdlib", "-no-pie",
            "-Wl,--build-id=none", "-Wl,-e,alt_call_fixture",
            SOURCE, "-o", binary,
        ],
        cwd=ROOT, text=True, capture_output=True, check=True,
    )
    symbols = {}
    nm = subprocess.run(
        [tools["nm"], "-S", binary], text=True, capture_output=True, check=True
    )
    for line in nm.stdout.splitlines():
        fields = line.split(maxsplit=3)
        if len(fields) == 4:
            symbols[fields[3]] = (int(fields[0], 16), int(fields[1], 16))
    disassembly = subprocess.run(
        [tools["objdump"], "-d", "--insn-width=16", binary],
        text=True, capture_output=True, check=True,
    ).stdout.splitlines()
    functions = {}
    for name in (
        "alt_call_fixture",
        "alt_call_pair",
        "alt_call_target",
        "alt_empty_fixture",
        "alt_empty_long_fixture",
        "alt_unregistered_fixture",
    ):
        start, size = symbols[name]
        instructions = []
        code = bytearray()
        for line in disassembly:
            fields = line.split("\t")
            if len(fields) < 3 or not fields[0].strip().endswith(":"):
                continue
            address = int(fields[0].strip()[:-1], 16)
            if start <= address < start + size:
                encoded = bytes.fromhex("".join(fields[1].split()))
                instructions.append((address - start, len(encoded)))
                code.extend(encoded)
        functions[name] = SimpleNamespace(
            start=start, size=size, instructions=tuple(instructions),
            code=bytes(code),
        )
    return SimpleNamespace(binary=binary, tools=tools, functions=functions)


def patched_direct(function, target):
    code = bytearray(function.code)
    sites = []
    for offset, size in function.instructions:
        if size == 6 and code[offset:offset + 2] == b"\xff\x15":
            displacement = target - (function.start + offset + size)
            assert -(1 << 31) <= displacement < (1 << 31)
            code[offset:offset + size] = b"\x2e\xe8" + struct.pack(
                "<i", displacement
            )
            sites.append(offset)
    return bytes(code), sites


def parse_functions(path):
    functions = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("FNDA:"):
            count, name = line[5:].split(",", 1)
            functions[name] = max(functions.get(name, 0), int(count))
    return functions


def parse_lines(path):
    lines = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("DA:"):
            number, count, *_ = line[3:].split(",")
            lines[int(number)] = int(count)
    return lines


def run_patch_trace(
    run_etrace, tmp_path, fixture, function, code, insns=None,
    vaddr=None, explicit_map=True,
):
    trace = tmp_path / f"{function.start:x}-{len(code)}.etrace"
    coverage = trace.with_suffix(".info")
    decoded = trace.with_suffix(".txt")
    if insns is None:
        insns = function.instructions
    if vaddr is None:
        vaddr = function.start
    trace.write_bytes(
        etrace_info(major=1)
        + etrace_tb_def(
            vaddr=vaddr, insns=insns, code=code,
        )
        + etrace_tb_exec(sequence=1, insn_count=len(insns))
    )
    args = [
        "--trace", trace,
        "--trace-output", decoded,
        "--elf", fixture.binary,
        "--nm", fixture.tools["nm"],
        "--dwarfdump", fixture.tools["dwarfdump"],
        "--coverage-format", "lcov",
        "--coverage-output", coverage,
        "--auto-map",
    ]
    if explicit_map:
        args += [
            "--address-map", f"{vaddr:x}:{function.start:x}:{len(code):x}",
        ]
    result = run_etrace(*args)
    return result, parse_functions(coverage), decoded


def replace_instruction(function, original, replacement):
    offset = function.code.index(original)
    assert len(replacement) == len(original)
    code = bytearray(function.code)
    code[offset:offset + len(original)] = replacement
    return bytes(code), offset


def test_accepts_registered_direct_call(run_etrace, tmp_path, alt_call_fixture):
    function = alt_call_fixture.functions["alt_call_fixture"]
    target = alt_call_fixture.functions["alt_call_target"].start + 4
    code, sites = patched_direct(function, target)
    assert len(sites) == 1

    result, functions, decoded = run_patch_trace(
        run_etrace, tmp_path, alt_call_fixture, function, code
    )

    assert result.returncode == 0, result.stderr
    assert functions["alt_call_fixture"] == 1
    assert "partially verified" not in result.stderr
    assert f" {function.start:x} {function.start + function.size:x}" in (
        decoded.read_text(encoding="ascii")
    )


def test_rejects_invalid_registered_call(run_etrace, tmp_path, alt_call_fixture):
    function = alt_call_fixture.functions["alt_call_fixture"]
    code = bytearray(function.code)
    site, size = function.instructions[1]
    assert size == 6
    code[site:site + size] = b"\x2e\xe9\x00\x00\x00\x00"

    result, functions, decoded = run_patch_trace(
        run_etrace, tmp_path, alt_call_fixture, function, bytes(code)
    )

    assert result.returncode == 0, result.stderr
    assert functions["alt_call_fixture"] == 1
    assert "1 partially verified execution events" in result.stderr
    assert f" {function.start:x} {function.start + site:x}" in (
        decoded.read_text(encoding="ascii")
    )


def test_rejects_direct_call_outside_image(
    run_etrace, tmp_path, alt_call_fixture
):
    function = alt_call_fixture.functions["alt_call_fixture"]
    code, sites = patched_direct(function, 0x1000)
    assert len(sites) == 1

    result, _, _ = run_patch_trace(
        run_etrace, tmp_path, alt_call_fixture, function, code
    )

    assert result.returncode == 0, result.stderr
    assert "1 partially verified execution events" in result.stderr


def test_rejects_change_outside_registered_call(
    run_etrace, tmp_path, alt_call_fixture
):
    function = alt_call_fixture.functions["alt_call_fixture"]
    target = alt_call_fixture.functions["alt_call_target"].start
    code, _ = patched_direct(function, target)
    code = b"\xcc" + code[1:]

    result, functions, _ = run_patch_trace(
        run_etrace, tmp_path, alt_call_fixture, function, code
    )

    assert result.returncode == 0, result.stderr
    assert functions["alt_call_fixture"] == 0


def test_accepts_multiple_registered_calls(
    run_etrace, tmp_path, alt_call_fixture
):
    function = alt_call_fixture.functions["alt_call_pair"]
    target = alt_call_fixture.functions["alt_call_target"].start
    code, sites = patched_direct(function, target)
    assert len(sites) == 2

    result, functions, _ = run_patch_trace(
        run_etrace, tmp_path, alt_call_fixture, function, code
    )

    assert result.returncode == 0, result.stderr
    assert functions["alt_call_pair"] == 1
    assert "partially verified" not in result.stderr


def test_accepts_registered_poison_instruction(
    run_etrace, tmp_path, alt_call_fixture
):
    function = alt_call_fixture.functions["alt_call_fixture"]
    site, _ = function.instructions[1]
    code = function.code[:site] + b"\x0f\x0b"
    insns = (function.instructions[0], (site, 2))

    result, functions, _ = run_patch_trace(
        run_etrace, tmp_path, alt_call_fixture, function, code, insns
    )

    assert result.returncode == 0, result.stderr
    assert functions["alt_call_fixture"] == 1
    assert "partially verified" not in result.stderr


@pytest.mark.parametrize("replacement", [b"\x66\x66\x90", b"\x0f\x1f\x00"])
def test_accepts_registered_empty_alternative(
    run_etrace, tmp_path, alt_call_fixture, replacement
):
    function = alt_call_fixture.functions["alt_empty_fixture"]
    code, _ = replace_instruction(function, b"\x0f\xae\xe8", replacement)

    result, functions, decoded = run_patch_trace(
        run_etrace, tmp_path, alt_call_fixture, function, code
    )
    lines = parse_lines(decoded.with_suffix(".info"))

    assert result.returncode == 0, result.stderr
    assert functions["alt_empty_fixture"] == 1
    assert all(lines[line] == 1 for line in range(60, 65))
    assert "partially verified" not in result.stderr


def test_accepts_original_at_registered_empty_alternative(
    run_etrace, tmp_path, alt_call_fixture
):
    function = alt_call_fixture.functions["alt_empty_fixture"]

    result, functions, _ = run_patch_trace(
        run_etrace, tmp_path, alt_call_fixture, function, function.code
    )

    assert result.returncode == 0, result.stderr
    assert functions["alt_empty_fixture"] == 1
    assert "partially verified" not in result.stderr


def test_accepts_empty_alternative_with_changed_instruction_boundaries(
    run_etrace, tmp_path, alt_call_fixture
):
    function = alt_call_fixture.functions["alt_empty_long_fixture"]
    replacement = b"\x66\x66\x90\x66\x90"
    code, site = replace_instruction(
        function, b"\xb8\x01\x00\x00\x00", replacement
    )
    assert site == 0

    result, functions, _ = run_patch_trace(
        run_etrace, tmp_path, alt_call_fixture, function, code,
        insns=((0, 3), (3, 2), (5, 1)),
    )

    assert result.returncode == 0, result.stderr
    assert functions["alt_empty_long_fixture"] == 1
    assert "partially verified" not in result.stderr


def test_rejects_unrecognized_registered_empty_alternative(
    run_etrace, tmp_path, alt_call_fixture
):
    function = alt_call_fixture.functions["alt_empty_fixture"]
    code, site = replace_instruction(
        function, b"\x0f\xae\xe8", b"\x0f\x1f\x01"
    )

    result, functions, decoded = run_patch_trace(
        run_etrace, tmp_path, alt_call_fixture, function, code
    )

    assert result.returncode == 0, result.stderr
    assert functions["alt_empty_fixture"] == 1
    assert "1 partially verified execution events" in result.stderr
    assert f" {function.start:x} {function.start + site:x}" in (
        decoded.read_text(encoding="ascii")
    )


def test_rejects_empty_alternative_at_unregistered_site(
    run_etrace, tmp_path, alt_call_fixture
):
    function = alt_call_fixture.functions["alt_unregistered_fixture"]
    code, site = replace_instruction(
        function, b"\x0f\xae\xe8", b"\x66\x66\x90"
    )

    result, functions, decoded = run_patch_trace(
        run_etrace, tmp_path, alt_call_fixture, function, code
    )

    assert result.returncode == 0, result.stderr
    assert functions["alt_unregistered_fixture"] == 1
    assert "1 partially verified execution events" in result.stderr
    assert f" {function.start:x} {function.start + site:x}" in (
        decoded.read_text(encoding="ascii")
    )


@pytest.mark.parametrize("side", ["before", "after"])
def test_rejects_change_outside_registered_empty_alternative(
    run_etrace, tmp_path, alt_call_fixture, side
):
    function = alt_call_fixture.functions["alt_empty_fixture"]
    code, site = replace_instruction(
        function, b"\x0f\xae\xe8", b"\x66\x66\x90"
    )
    code = bytearray(code)
    changed = site - 1 if side == "before" else site + 3
    code[changed] ^= 1

    result, functions, _ = run_patch_trace(
        run_etrace, tmp_path, alt_call_fixture, function, bytes(code)
    )

    assert result.returncode == 0, result.stderr
    assert functions["alt_empty_fixture"] == (side == "after")
    if side == "after":
        assert "partially verified" in result.stderr
    else:
        assert "1 execution events in 1 unresolved aggregates" in result.stderr


def test_rejects_partial_registered_empty_alternative(
    run_etrace, tmp_path, alt_call_fixture
):
    function = alt_call_fixture.functions["alt_empty_long_fixture"]
    replacement = b"\x66\x66\x90\x66\x90"
    code, site = replace_instruction(
        function, b"\xb8\x01\x00\x00\x00", replacement
    )
    assert site == 0

    result, functions, _ = run_patch_trace(
        run_etrace, tmp_path, alt_call_fixture, function,
        code[:3], insns=((0, 3),)
    )

    assert result.returncode == 0, result.stderr
    assert functions["alt_empty_long_fixture"] == 0
    assert "1 execution events in 1 unresolved aggregates" in result.stderr


def test_registered_empty_alternative_does_not_establish_mapping(
    run_etrace, tmp_path, alt_call_fixture
):
    function = alt_call_fixture.functions["alt_empty_fixture"]
    code, _ = replace_instruction(
        function, b"\x0f\xae\xe8", b"\x66\x66\x90"
    )

    result, functions, _ = run_patch_trace(
        run_etrace, tmp_path, alt_call_fixture, function, code,
        explicit_map=False,
    )

    assert result.returncode == 0, result.stderr
    assert functions["alt_empty_fixture"] == 0
    assert "1 execution events in 1 unresolved aggregates" in result.stderr
