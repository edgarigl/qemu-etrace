"""Fixture-only probes of GCC dump timing, not a source-provenance parser."""

import json
from pathlib import Path
import re
import shutil
import subprocess

import pytest

pytest.importorskip("elftools")
from elftools.elf.elffile import ELFFile

from research.gcc_provenance import audit_returns, identity, witness_observed
from tests.test_gcc_provenance import exec_sections


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "tests/fixtures/compiler-return-origins.c"
START = ROOT / "tests/fixtures/compiler-returns-start.S"
FUNCTIONS = (
    "terminal_return", "folded_origins", "branchless_origins", "macro_origins",
    "explicit_and_implicit", "discarded_fallthrough", "constant_dead_return",
    "same_line_origins",
)


def dump_body(text, function):
    # These fixed fixtures have single-line int/void signatures and no nested
    # functions. Do not use this convenience extractor on arbitrary GCC dumps.
    matches = list(re.finditer(r"^(?:int|void) " + re.escape(function)
                              + r" \(int x\)\n", text, re.M))
    assert len(matches) == 1, function
    tail = text[matches[0].end():]
    end = re.search(r"^}\s*$", tail, re.M)
    assert end is not None, function
    return tail[:end.start()]


def dumped_returns(text, function):
    locations = []
    for line in dump_body(text, function).splitlines():
        match = re.fullmatch(r"\s*(?:\[(.*)\] )?return(?: .*|;)", line)
        if match:
            location = match[1]
            if location is not None:
                parsed = re.fullmatch(r"(.*):(\d+):(\d+)(?: discrim (\d+))?", location)
                assert parsed is not None, location
                location = {"source": parsed[1], "line": int(parsed[2]),
                            "column": int(parsed[3]), "discriminator": parsed[4]}
            locations.append(location)
    return locations


def code_relocations(path):
    with path.open("rb") as stream:
        elf = ELFFile(stream)
        result = []
        for section in elf.iter_sections():
            if section["sh_type"] != "SHT_RELA":
                continue
            target = elf.get_section(section["sh_info"])
            if not target["sh_flags"] & 4:
                continue
            symbols = elf.get_section(section["sh_link"])
            for relocation in section.iter_relocations():
                symbol = symbols.get_symbol(relocation["r_info_sym"])
                result.append((target.name, relocation["r_offset"], relocation["r_info_type"],
                               symbol.name, relocation["r_addend"]))
        return result


@pytest.fixture(scope="module", params=["x86_64-linux-gnu-gcc-13", "x86_64-linux-gnu-gcc-14"])
def origin_compiler(request):
    compiler = shutil.which(request.param)
    if compiler is None:
        pytest.skip(f"{request.param} required for this dump-format experiment")
    return compiler


@pytest.fixture(scope="module", params=[False, True], ids=["ret", "thunk"])
def origin_build(tmp_path_factory, origin_compiler, request):
    objdump = shutil.which("x86_64-linux-gnu-objdump") or shutil.which("objdump")
    if objdump is None:
        pytest.skip("x86 objdump required")
    directory = tmp_path_factory.mktemp(Path(origin_compiler).name + "-origins")
    args = [origin_compiler, "-O2", "-g", "-fno-pie", "-fcf-protection=none",
            "-ffunction-sections", "-fno-asynchronous-unwind-tables"]
    if request.param:
        args.append("-mfunction-return=thunk-extern")
    commands = []

    def run(command):
        commands.append([str(arg) for arg in command])
        subprocess.run(command, capture_output=True, check=True)

    for mode in ("diagnostic", "plain"):
        output = directory / mode
        output.mkdir()
        flags = []
        if mode == "diagnostic":
            flags = ["-save-temps=obj", "-dA", "-dp", "-fverbose-asm",
                     "-fdump-tree-original-lineno", "-fdump-tree-gimple-lineno",
                     "-fdump-tree-cfg-lineno", "-fdump-tree-optimized-lineno",
                     "-fdump-rtl-final", "-Wa,-adhln=" + str(output / "origins.lst")]
        run([*args, *flags, "-c", SOURCE, "-o", output / "origins.o"])
        run([origin_compiler, "-nostdlib", "-no-pie", "-Wl,--build-id=none",
             START, output / "origins.o", "-o", output / "origins"])
    diagnostic = directory / "diagnostic"
    inputs = {
        "assembly": diagnostic / "origins.s", "listing": diagnostic / "origins.lst",
        "rtl": next(diagnostic.glob("*r.final")), "obj": diagnostic / "origins.o",
        "elf": diagnostic / "origins", "objdump": objdump,
    }
    dumps = {stage: next(diagnostic.glob("*t." + stage)).read_text()
             for stage in ("gimple", "cfg", "optimized")}
    records = {function: audit_returns(**inputs, function=function)
               for function in FUNCTIONS}
    # Preserve the exact experiment inputs/outputs for --basetemp handoffs.
    summary = {
        "kind": "gcc-return-origin-fixture-experiment", "version": 1,
        "compiler": subprocess.check_output([origin_compiler, "--version"], text=True),
        "commands": commands, "source": identity(SOURCE), "start": identity(START),
        "code_identity": {
            name: exec_sections(directory / "diagnostic" / name)
                  == exec_sections(directory / "plain" / name)
            for name in ("origins.o", "origins")
        },
        "code_relocations_identical": code_relocations(directory / "diagnostic/origins.o")
                                      == code_relocations(directory / "plain/origins.o"),
        "functions": {
            function: {**{stage: dumped_returns(text, function) for stage, text in dumps.items()},
                       "machine_audit": records[function], "source_association": "unresolved",
                       "coverage_candidate": False}
            for function in FUNCTIONS
        },
        "artifacts": {str(path.relative_to(directory)): identity(path)["sha256"]
                      for path in directory.rglob("*") if path.is_file()},
    }
    (directory / "origins-summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    return {"directory": directory, "inputs": inputs, "summary": summary}


def test_origin_dumps_preserve_code(origin_build):
    assert all(origin_build["summary"]["code_identity"].values())
    assert origin_build["summary"]["code_relocations_identical"]
    # Debug sections may differ: the producer records diagnostic flags.
    with origin_build["inputs"]["elf"].open("rb") as stream:
        symbols = ELFFile(stream).get_section_by_name(".symtab")
        assert not any("gcov" in symbol.name for symbol in symbols.iter_symbols())


@pytest.mark.parametrize("function", ["folded_origins", "branchless_origins", "macro_origins",
                                      "constant_dead_return", "same_line_origins"])
def test_cfg_already_merges_or_removes_return_origins(origin_build, function):
    record = origin_build["summary"]["functions"][function]
    assert len(record["gimple"]) == 2
    assert all(location is not None for location in record["gimple"])
    assert len(record["cfg"]) == len(record["optimized"]) == 1
    assert len(record["machine_audit"]["returns"]) == 1
    assert record["source_association"] == "unresolved"
    assert record["coverage_candidate"] is False
    if function == "same_line_origins":
        first, second = record["gimple"]
        assert first["line"] == second["line"]
        assert first["column"] != second["column"]
    if function == "macro_origins":
        first = record["gimple"][0]
        assert "RETURN_VALUE(1)" in SOURCE.read_text().splitlines()[first["line"] - 1]


def test_one_explicit_return_does_not_exclude_fallthrough(origin_build):
    functions = origin_build["summary"]["functions"]
    for name in ("terminal_return", "explicit_and_implicit", "discarded_fallthrough"):
        record = functions[name]
        assert len(record["gimple"]) == 1
        assert record["gimple"][0] is not None
        expected = 2 if name == "discarded_fallthrough" else 1
        assert len(record["machine_audit"]["returns"]) == expected
        assert record["coverage_candidate"] is False
    assert len(functions["terminal_return"]["cfg"]) == 1
    # GCC has already merged the explicit void return with an implicit exit.
    assert functions["explicit_and_implicit"]["cfg"] == [None]
    # For the nonvoid example, the extra CFG return points at the closing brace.
    explicit, implicit = functions["discarded_fallthrough"]["cfg"]
    assert explicit["line"] == functions["discarded_fallthrough"]["gimple"][0]["line"]
    assert SOURCE.read_text().splitlines()[implicit["line"] - 1] == "}"


def test_real_implicit_and_explicit_exits_share_pcs(origin_build):
    qemu = shutil.which("qemu-x86_64")
    if qemu is None:
        pytest.skip("qemu-x86_64 required for runtime counterexamples")
    directory = origin_build["directory"]
    binary = origin_build["inputs"]["elf"]
    functions = ("explicit_and_implicit", "discarded_fallthrough", "branchless_origins")
    with binary.open("rb") as stream:
        elf = ELFFile(stream)
        bounds = {symbol.name: (symbol["st_value"], symbol["st_value"] + symbol["st_size"])
                  for symbol in elf.get_section_by_name(".symtab").iter_symbols()
                  if symbol.name in functions}
    runs = []
    for x, expected in ((0, 3), (1, 9)):
        log = directory / f"qemu-{x}.log"
        command = [qemu, "-one-insn-per-tb", "-d", "exec,nochain", "-D", str(log),
                   str(binary), *(["x"] * x)]
        run = subprocess.run(command, capture_output=True, timeout=30)
        assert run.returncode == expected, run.stderr
        pcs = [int(pc, 16) for pc in re.findall(r"\[[0-9a-f]+/([0-9a-f]+)/", log.read_text())]
        observed = {}
        for function in functions:
            low, high = bounds[function]
            path = [pc for pc in pcs if low <= pc < high]
            assert path
            returns = origin_build["summary"]["functions"][function]["machine_audit"]["returns"]
            record, = [record for record in returns if int(record["witness_start"], 16) in path]
            start, end = int(record["witness_start"], 16), int(record["witness_end"], 16)
            assert start in path
            # One instruction per TB; the exact ELF/audit supplies its size.
            assert witness_observed(record, [(start, end)])
            observed[function] = [hex(pc) for pc in path]
        runs.append({"x": x, "command": command, "exit_status": run.returncode,
                     "log": identity(log), "function_pcs": observed})
    same_paths = [name for name in functions
                  if runs[0]["function_pcs"][name] == runs[1]["function_pcs"][name]]
    assert same_paths == ["explicit_and_implicit", "branchless_origins"]
    (directory / "runtime-summary.json").write_text(json.dumps({
        "kind": "qemu-user-fixture", "elf": identity(binary),
        "qemu": subprocess.check_output([qemu, "--version"], text=True),
        "runs": runs, "same_pcs_for_different_source_paths": same_paths,
        "source_association": "unresolved", "coverage_candidate": False,
    }, indent=2) + "\n")
