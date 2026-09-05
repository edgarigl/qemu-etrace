from pathlib import Path
import shutil
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"


def installed_compilers():
    compilers = []
    seen = set()
    for name in ["gcc", *(f"gcc-{version}" for version in range(4, 30))]:
        path = shutil.which(name)
        if path is None:
            continue
        real_path = Path(path).resolve()
        if real_path in seen:
            continue
        seen.add(real_path)
        compilers.append((name, path))
    return compilers


def symbol_count_and_range(binary, name):
    result = subprocess.run(
        ["nm", "-S", str(binary)],
        text=True,
        capture_output=True,
        check=True,
    )
    matches = []
    for line in result.stdout.splitlines():
        fields = line.split(maxsplit=3)
        if len(fields) == 4 and fields[3] == name:
            matches.append((int(fields[0], 16), int(fields[1], 16)))
    return matches


def inline_addresses(binary, caller, inline):
    [(start, size)] = symbol_count_and_range(binary, caller)
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
        if inline in result.stdout.splitlines()[::2]:
            addresses.append(address)
    return addresses


def run_source_coverage(run_etrace, tmp_path, binary, address, name,
                        function):
    trace = tmp_path / f"{name}.hex"
    output = tmp_path / f"{name}.info"
    trace.write_text(f"{address:x}\n", encoding="ascii")
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
        "source",
    )
    assert result.returncode == 0
    return [
        line
        for line in output.read_text(encoding="utf-8").splitlines()
        if line.startswith("FNDA:") and line.endswith(f",{function}")
    ]


@pytest.mark.parametrize(
    "compiler",
    [path for _, path in installed_compilers()],
    ids=[name for name, _ in installed_compilers()],
)
def test_inline_entry_and_shared_tail_across_gcc(compiler, run_etrace, tmp_path):
    if shutil.which("dwarfdump") is None or shutil.which("addr2line") is None:
        pytest.skip("dwarfdump and addr2line are required")

    binary = tmp_path / "inline-function"
    subprocess.run(
        [
            compiler,
            "-O2",
            "-g",
            "-fno-pie",
            "-no-pie",
            str(FIXTURES / "inline-function.c"),
            "-o",
            str(binary),
        ],
        check=True,
    )

    assert len(symbol_count_and_range(binary, "inline_helper")) == 1
    addresses = inline_addresses(binary, "call_inline_helper", "inline_helper")
    assert len(addresses) >= 2

    assert run_source_coverage(
        run_etrace, tmp_path, binary, addresses[0], "entry", "inline_helper"
    ) == ["FNDA:1,inline_helper"]
    assert run_source_coverage(
        run_etrace, tmp_path, binary, addresses[-1], "tail", "inline_helper"
    ) == ["FNDA:0,inline_helper"]
