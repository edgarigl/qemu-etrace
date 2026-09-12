from pathlib import Path
import json
import shutil
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / ".test-build" / "inline-function-fixture"
DUPLICATE_FIXTURE = ROOT / ".test-build" / "duplicate-inline-fixture"
DECLARATION_SOURCE = ROOT / "tests" / "fixtures" / "function-declarations.cc"


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


def function_declarations(output):
    declarations = {}
    for line in output.read_text(encoding="utf-8").splitlines():
        if line.startswith("FN:"):
            number, name = line[3:].split(",", 1)
            declarations[name] = int(number)
    return declarations


def line_counts(output):
    lines = {}
    for line in output.read_text(encoding="utf-8").splitlines():
        if line.startswith("DA:"):
            number, count, *_ = line[3:].split(",")
            lines[int(number)] = int(count)
    return lines


def run_coverage(run_etrace, tmp_path, policy, address, *extra_args,
                 binary=FIXTURE, objdump=None):
    trace = tmp_path / f"{policy}.hex"
    output = tmp_path / f"{policy}.info"
    addresses = (address,) if isinstance(address, int) else address
    trace.write_text(
        "".join(f"{item:x}\n" for item in addresses),
        encoding="ascii",
    )

    result = run_etrace(
        "--trace",
        trace,
        "--trace-in-format",
        "ascii-hex",
        "--trace-output",
        "none",
        "--elf",
        binary,
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
        *(() if objdump is None else ("--objdump", objdump)),
    )

    assert result.returncode == 0, result.stderr
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


def test_lcov_uses_dwarf_subprogram_declaration_coordinates(
    run_etrace, tmp_path
):
    if shutil.which("dwarfdump") is None:
        pytest.skip("dwarfdump is required")
    start, _ = symbol_range("call_inline_helper")
    trace = tmp_path / "declaration.hex"
    output = tmp_path / "declaration.info"
    inventory = tmp_path / "declaration.jsonl"
    trace.write_text(f"{start:x}\n", encoding="ascii")

    result = run_etrace(
        "--trace", trace,
        "--trace-in-format", "ascii-hex",
        "--trace-output", "none",
        "--elf", FIXTURE,
        "--dwarfdump", shutil.which("dwarfdump"),
        "--coverage-format", "lcov",
        "--coverage-output", output,
        "--coverage-inventory", inventory,
    )

    assert result.returncode == 0, result.stderr
    declarations = function_declarations(output)
    assert declarations["inline_helper"] == 1
    assert declarations["call_inline_helper"] == 10
    assert declarations["main"] == 15
    records = {
        record["name"]: record
        for line in inventory.read_text(encoding="utf-8").splitlines()
        if (record := json.loads(line))
    }
    assert records["call_inline_helper"]["line"] == 10
    assert records["call_inline_helper"]["source_confidence"] == (
        "dwarf-declaration"
    )


def test_function_entry_line_policy_is_explicit_and_uses_function_count(
    run_etrace, tmp_path
):
    if shutil.which("dwarfdump") is None:
        pytest.skip("dwarfdump is required")
    start, _ = symbol_range("call_inline_helper")
    trace = tmp_path / "line-policy.hex"
    trace.write_text(f"{start:x}\n" * 3, encoding="ascii")

    outputs = {}
    for policy in (None, "address", "function-entry"):
        output = tmp_path / f"line-policy-{policy or 'default'}.info"
        arguments = [
            "--trace", trace,
            "--trace-in-format", "ascii-hex",
            "--trace-output", "none",
            "--elf", FIXTURE,
            "--dwarfdump", shutil.which("dwarfdump"),
            "--coverage-format", "lcov",
            "--coverage-output", output,
        ]
        if policy is not None:
            arguments += ["--line-hit-policy", policy]
        result = run_etrace(*arguments)
        assert result.returncode == 0, result.stderr
        outputs[policy] = output

    assert outputs[None].read_bytes() == outputs["address"].read_bytes()
    assert 10 not in line_counts(outputs[None])
    assert function_counts(outputs["function-entry"])[
        "call_inline_helper"
    ] == 3
    assert line_counts(outputs["function-entry"])[10] == 3


@pytest.mark.parametrize("compiler_name", ["g++", "clang++-18"])
def test_lcov_resolves_dwarf_specification_declaration(
    run_etrace, tmp_path, compiler_name
):
    compiler = shutil.which(compiler_name)
    if compiler is None or shutil.which("dwarfdump") is None:
        pytest.skip("C++ compiler and dwarfdump are required")
    binary = tmp_path / "function-declarations"
    build = subprocess.run(
        [compiler, "-O2", "-g", "-fno-pie", "-no-pie",
         "-Wl,--build-id=none", DECLARATION_SOURCE, "-o", binary],
        text=True, capture_output=True,
    )
    if build.returncode:
        pytest.skip(f"compiler cannot build declaration fixture: {build.stderr}")
    symbols = subprocess.run(
        ["nm", "-S", "-C", binary], text=True, capture_output=True, check=True
    ).stdout.splitlines()
    name, start = next(
        (fields[3], int(fields[0], 16))
        for line in symbols
        if len(fields := line.split(maxsplit=3)) == 4
        and fields[3] == "Worker::run(int)"
    )
    trace = tmp_path / "specification.hex"
    output = tmp_path / "specification.info"
    trace.write_text(f"{start:x}\n", encoding="ascii")

    result = run_etrace(
        "--trace", trace,
        "--trace-in-format", "ascii-hex",
        "--trace-output", "none",
        "--elf", binary,
        "--dwarfdump", shutil.which("dwarfdump"),
        "--coverage-format", "lcov",
        "--coverage-output", output,
    )

    assert result.returncode == 0, result.stderr
    assert function_declarations(output)[name] == 7


def test_source_policy_ignores_jump_into_inline_range(run_etrace, tmp_path):
    if shutil.which("dwarfdump") is None or shutil.which("addr2line") is None:
        pytest.skip("dwarfdump and addr2line are required")

    addresses = inline_body_addresses()
    if len(addresses) < 2:
        pytest.skip("compiler emitted only one inline-attributed bucket")

    source_counts = run_coverage(run_etrace, tmp_path, "source", addresses[-1])

    assert source_counts["inline_helper"] == 0


def test_source_policy_counts_validated_alternate_inline_entry(
    run_etrace, tmp_path
):
    tools = {
        "cc": shutil.which("x86_64-linux-gnu-gcc"),
        "nm": shutil.which("x86_64-linux-gnu-nm"),
        "objdump": shutil.which("x86_64-linux-gnu-objdump"),
        "addr2line": shutil.which("addr2line"),
        "dwarfdump": shutil.which("dwarfdump"),
    }
    if any(value is None for value in tools.values()):
        pytest.skip("x86 compiler and DWARF tools are required")
    binary = tmp_path / "inline-entry-clone"
    source = ROOT / "tests/fixtures/inline-entry-clone.c"
    build = subprocess.run(
        [tools["cc"], "-O2", "-g", "-fno-pie", "-fno-stack-protector",
         "-fomit-frame-pointer", "-fprofile-arcs", "-ftest-coverage",
         "-fprofile-update=atomic", "-no-pie", "--coverage", source,
         "-o", binary],
        text=True, capture_output=True,
    )
    if build.returncode:
        pytest.skip(f"x86 compiler cannot build coverage fixture: {build.stderr}")
    disassembly = subprocess.run(
        [tools["objdump"], "-d", "--disassemble=elf_access_ok", binary],
        text=True, capture_output=True, check=True,
    ).stdout
    comparisons = [
        int(line.split(":", 1)[0], 16)
        for line in disassembly.splitlines()
        if "cmpq" in line and "0x98(" in line
    ]
    assert len(comparisons) == 2
    declared, alternate = comparisons
    stores = [
        int(line.split(":", 1)[0], 16)
        for line in disassembly.splitlines()
        if "movq" in line and "0x98(" in line
    ]
    assert len(stores) == 1

    entry_counts = run_coverage(
        run_etrace, tmp_path, "source", declared, binary=binary,
        objdump=tools["objdump"],
    )
    alternate_counts = run_coverage(
        run_etrace, tmp_path, "source", alternate, binary=binary,
        objdump=tools["objdump"],
    )
    store_counts = run_coverage(
        run_etrace, tmp_path, "source", stores[0], binary=binary,
        objdump=tools["objdump"],
    )
    assert entry_counts["elf_mark_broken"] == 1
    assert alternate_counts["elf_mark_broken"] == 1
    assert store_counts["elf_mark_broken"] == 0


@pytest.mark.parametrize(
    ("out_of_line_executions", "inline_executions"),
    [(2, 3), (4, 2)],
)
def test_source_policy_uses_maximum_function_entry_count(
    run_etrace,
    tmp_path,
    out_of_line_executions,
    inline_executions,
):
    if shutil.which("dwarfdump") is None or shutil.which("addr2line") is None:
        pytest.skip("dwarfdump and addr2line are required")

    out_of_line_entry, _ = symbol_range("inline_helper")
    inline_entry = inline_body_addresses()[0]
    addresses = (
        [out_of_line_entry] * out_of_line_executions
        + [inline_entry] * inline_executions
    )

    entry_counts = run_coverage(
        run_etrace,
        tmp_path,
        "entry",
        addresses,
    )
    source_counts = run_coverage(
        run_etrace,
        tmp_path,
        "source",
        addresses,
    )

    assert entry_counts["inline_helper"] == out_of_line_executions
    assert source_counts["inline_helper"] == max(
        out_of_line_executions,
        inline_executions,
    )
    assert source_counts["inline_helper"] >= entry_counts["inline_helper"]


def test_lcov_deduplicates_retained_inline_symbols(run_etrace, tmp_path):
    if shutil.which("dwarfdump") is None:
        pytest.skip("dwarfdump is required")

    symbols = subprocess.run(
        ["nm", "-S", str(DUPLICATE_FIXTURE)],
        text=True,
        capture_output=True,
        check=True,
    )
    helper_addresses = [
        int(line.split()[0], 16)
        for line in symbols.stdout.splitlines()
        if line.split(maxsplit=3)[-1] == "shared_inline_helper"
    ]
    assert len(helper_addresses) == 2
    trace = tmp_path / "duplicate.hex"
    output = tmp_path / "duplicate.info"
    trace.write_text(f"{helper_addresses[0]:x}\n", encoding="ascii")

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
        "--coverage-format",
        "lcov",
        "--coverage-output",
        output,
        "--function-hit-policy",
        "entry",
    )

    assert result.returncode == 0
    records = function_records(output, "shared_inline_helper")
    assert len(records) == 1
    assert records[0] == "FNDA:1,shared_inline_helper"


@pytest.mark.parametrize("policy", ["entry", "source"])
def test_address_map_applies_to_function_policy(run_etrace, tmp_path, policy):
    if shutil.which("dwarfdump") is None or shutil.which("addr2line") is None:
        pytest.skip("dwarfdump and addr2line are required")

    linked = inline_body_addresses()[0]
    runtime = 0x40000000
    expected = run_coverage(run_etrace, tmp_path, policy, linked)
    actual = run_coverage(
        run_etrace,
        tmp_path,
        policy,
        runtime,
        "--address-map",
        f"{runtime:x}:{linked:x}:4",
    )

    assert actual == expected
