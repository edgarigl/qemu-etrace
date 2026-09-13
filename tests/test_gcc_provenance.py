from pathlib import Path
import re
import shutil
import subprocess

import pytest

pytest.importorskip("elftools")
from elftools.elf.elffile import ELFFile

from research.gcc_provenance import (
    AuditError, audit_returns, assembly_blocks, listing_rows, rtl_function,
    witness_observed,
)
from tests.test_assembly_fixture import find_x86_compiler
from tests.test_assembly_fixture import parse_lcov
from tests.trace_builder import etrace_arch, etrace_exec64


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "tests/fixtures/compiler-returns.c"
START = ROOT / "tests/fixtures/compiler-returns-start.S"


def compile_fixture(directory, compiler, annotated, thunk):
    obj, binary = directory / "returns.o", directory / "returns"
    command = [compiler, "-O2", "-g", "-fno-pie", "-fcf-protection=none",
               "-ffunction-sections", "-fno-asynchronous-unwind-tables"]
    if thunk:
        command.append("-mfunction-return=thunk-extern")
    if annotated:
        command += ["-save-temps=obj", "-dA", "-dp", "-fverbose-asm",
                    "-fdump-rtl-final", "-fdump-tree-optimized-lineno-blocks",
                    "-Wa,-adhln=" + str(directory / "returns.lst")]
    subprocess.run([*command, "-c", SOURCE, "-o", obj], check=True, capture_output=True)
    subprocess.run([compiler, "-nostdlib", "-no-pie", "-Wl,--build-id=none",
                    START, obj, "-o", binary], check=True, capture_output=True)
    return obj, binary


@pytest.fixture(scope="module", params=[False, True], ids=["ret", "thunk"])
def compiled_returns(tmp_path_factory, request):
    compiler = find_x86_compiler()
    objdump = shutil.which("x86_64-linux-gnu-objdump") or shutil.which("objdump")
    if compiler is None or objdump is None:
        pytest.skip("x86 GCC and objdump required")
    root = tmp_path_factory.mktemp("compiler-returns")
    directory, plain = root / "annotated", root / "plain"
    directory.mkdir()
    plain.mkdir()
    obj, binary = compile_fixture(directory, compiler, True, request.param)
    plain_obj, plain_binary = compile_fixture(plain, compiler, False, request.param)
    return {
        "assembly": directory / "returns.s", "listing": directory / "returns.lst",
        "rtl": next(directory.glob("*r.final")), "obj": obj, "elf": binary,
        "objdump": objdump, "plain_obj": plain_obj, "plain_elf": plain_binary,
    }


def audit(compiled, function="single_return", **changes):
    args = {name: value for name, value in compiled.items() if not name.startswith("plain_")}
    args.update(changes)
    return audit_returns(**args, function=function)


def exec_sections(path):
    with path.open("rb") as stream:
        elf = ELFFile(stream)
        return {section.name: (section["sh_addr"], section.data())
                for section in elf.iter_sections() if section["sh_flags"] & 4}


def test_diagnostics_preserve_executable_code(compiled_returns):
    for key in ("obj", "elf"):
        assert exec_sections(compiled_returns[key]) == exec_sections(compiled_returns["plain_" + key])


def test_derive_returns_and_require_terminal_witness(compiled_returns):
    result = audit(compiled_returns)
    assert result["inputs"]["elf"]["sha256"]
    assert len(result["returns"]) >= 2
    for record in result["returns"]:
        assert record["byte_mapping"] == "verified"
        assert record["source_association"] == "unresolved"
        assert record["coverage_candidate"] is False
        start, end = int(record["linked_start"], 16), int(record["linked_end"], 16)
        witness = int(record["witness_start"], 16)
        assert record["instructions"][-1]["return"]
        assert witness_observed(record, [(witness, end)])
        assert not witness_observed(record, [(start, witness)])
        assert not witness_observed(record, [(witness, end - 1)])
        assert not witness_observed(record, [])


@pytest.mark.parametrize("function", ["folded_returns", "branchless_returns"])
def test_folded_source_returns_do_not_become_source_hits(compiled_returns, function):
    result = audit(compiled_returns, function)
    assert len(result["returns"]) == 1
    assert result["returns"][0]["coverage_candidate"] is False
    assert result["returns"][0]["source_association"] == "unresolved"


def test_reject_wrong_rtl_identity(compiled_returns, tmp_path):
    record = audit(compiled_returns)["returns"][0]
    uid = record["instructions"][0]["rtl_uid"]
    text = compiled_returns["rtl"].read_text()
    # Change just this function's instruction; IDs repeat in other functions.
    before, body = text.split(";; Function single_return ", 1)
    body, count = re.subn(r"^(\((?:insn|jump_insn)(?:/[a-z]+)?(?::\w+)? )" + str(uid) + r" ",
                         r"\g<1>999999 ", body, count=1, flags=re.M)
    assert count == 1
    path = tmp_path / "wrong.final"
    path.write_text(before + ";; Function single_return " + body)
    with pytest.raises(AuditError, match="identity|ID mismatch"):
        audit(compiled_returns, rtl=path)


def test_reject_wrong_listing_bytes(compiled_returns, tmp_path):
    record = audit(compiled_returns)["returns"][0]
    number = record["instructions"][-1]["assembly_line"]
    text = compiled_returns["listing"].read_text()
    text, count = re.subn(r"^(\s*" + str(number) + r" +[0-9a-fA-F]+ +)[0-9A-Fa-f]{2}",
                         r"\g<1>00", text, count=1, flags=re.M)
    assert count == 1
    path = tmp_path / "wrong.lst"
    path.write_text(text)
    with pytest.raises(AuditError, match="listing bytes"):
        audit(compiled_returns, listing=path)


def test_reject_changed_linked_code(compiled_returns, tmp_path):
    record = audit(compiled_returns)["returns"][0]
    address = int(record["witness_start"], 16)
    with compiled_returns["elf"].open("rb") as stream:
        elf = ELFFile(stream)
        section = next(s for s in elf.iter_sections()
                       if s["sh_addr"] <= address < s["sh_addr"] + s["sh_size"])
        offset = section["sh_offset"] + address - section["sh_addr"]
    data = bytearray(compiled_returns["elf"].read_bytes())
    data[offset] ^= 1
    path = tmp_path / "wrong.elf"
    path.write_bytes(data)
    with pytest.raises(AuditError, match="differ from linked"):
        audit(compiled_returns, elf=path)


def test_reject_duplicate_listing_row(compiled_returns, tmp_path):
    record = audit(compiled_returns)["returns"][0]
    number = record["instructions"][0]["assembly_line"]
    text = compiled_returns["listing"].read_text()
    row = next(line for line in text.splitlines()
               if re.match(r"\s*" + str(number) + r" +[0-9a-fA-F]+ +[0-9a-fA-F]+ *\t", line))
    path = tmp_path / "duplicate.lst"
    path.write_text(text + "\n" + row + "\n")
    with pytest.raises(AuditError, match="ambiguous listing"):
        audit(compiled_returns, listing=path)


def test_audit_does_not_change_lcov(compiled_returns, run_etrace, tmp_path):
    if shutil.which("dwarfdump") is None:
        pytest.skip("dwarfdump required")
    with compiled_returns["elf"].open("rb") as stream:
        elf = ELFFile(stream)
        symbol, = [s for s in elf.get_section_by_name(".symtab").iter_symbols()
                   if s.name == "single_return"]
        start, end = symbol["st_value"], symbol["st_value"] + symbol["st_size"]
    trace = tmp_path / "synthetic.etrace"
    trace.write_bytes(etrace_arch(guest_bits=64) + etrace_exec64(start=start, end=end))
    output = tmp_path / "baseline.info"
    args = ["--trace", trace, "--elf", compiled_returns["elf"], "--trace-output", "none",
            "--coverage-format", "lcov", "--coverage-output", output]
    result = run_etrace(*args)
    assert result.returncode == 0, result.stderr
    baseline = output.read_bytes()
    assert parse_lcov(output)
    audit(compiled_returns)
    result = run_etrace(*args)
    assert result.returncode == 0, result.stderr
    assert output.read_bytes() == baseline


def test_listing_continuations():
    rows = listing_rows(" 10 004f E9000000 \t\tjmp\tthunk\n 10      00\n")
    assert rows[10][0][1] == b"\xe9\0\0\0\0"


def test_reject_ambiguous_function():
    with pytest.raises(AuditError, match="ambiguous"):
        assembly_blocks("f:\nf:\n", "f")
    with pytest.raises(AuditError, match="ambiguous"):
        rtl_function(";; Function f (f)\n;; Function f (f)\n", "f")


def test_real_qemu_execution_witness(compiled_returns, tmp_path):
    qemu = shutil.which("qemu-x86_64")
    if qemu is None:
        pytest.skip("qemu-x86_64 required for real execution witness")
    records = audit(compiled_returns)["returns"]
    witnessed = set()
    branchless = audit(compiled_returns, "branchless_returns")["returns"][0]
    branch_pcs = []
    for count, expected in ((0, 9), (1, 5), (2, 11)):
        log = tmp_path / f"run-{count}.log"
        run = subprocess.run([qemu, "-one-insn-per-tb", "-d", "exec,nochain", "-D", log,
                              compiled_returns["elf"], *(["x"] * count)], capture_output=True)
        assert run.returncode == expected, run.stderr
        pcs = [int(pc, 16) for pc in re.findall(r"\[[0-9a-f]+/([0-9a-f]+)/", log.read_text())]
        branch_pcs.append([pc for pc in pcs if int(branchless["linked_start"], 16)
                           <= pc < int(branchless["linked_end"], 16)])
        for record in records:
            start, end = int(record["witness_start"], 16), int(record["witness_end"], 16)
            if start in pcs:
                assert witness_observed(record, [(start, end)])
                witnessed.add(record["final_block"])
    assert len(witnessed) >= 2
    assert branch_pcs[0] and branch_pcs[0] == branch_pcs[1] == branch_pcs[2]
