import os
from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[1]


def make_flags(tmp_path, use_local=None):
    makefile = tmp_path / "print-flags.mk"
    makefile.write_text(
        f"include {ROOT}/Makefile\n"
        "print-flags:\n"
        "\t@echo CPPFLAGS=$(CPPFLAGS)\n"
        "\t@echo LDFLAGS=$(LDFLAGS)\n"
        "\t@echo LDLIBS=$(LDLIBS)\n",
        encoding="ascii",
    )
    command = ["make", "-s", "-f", str(makefile), "print-flags"]
    if use_local is not None:
        command.append(f"USE_LOCAL_BINUTILS={use_local}")
    env = os.environ.copy()
    env.pop("MAKEFLAGS", None)
    env.pop("MFLAGS", None)
    env.pop("USE_LOCAL_BINUTILS", None)
    result = subprocess.run(
        command,
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=True,
    )
    return result.stdout.splitlines()


def test_system_binutils_is_default(tmp_path):
    flags = make_flags(tmp_path)

    assert not any("binutils-2.42-install" in line for line in flags)
    assert "-liberty" not in flags[-1].split()


def test_local_binutils_adds_prefix_and_libiberty(tmp_path):
    flags = make_flags(tmp_path, 1)

    assert any("binutils-2.42-install/include" in line for line in flags)
    assert any("binutils-2.42-install/lib" in line for line in flags)
    assert "-liberty" in flags[-1].split()
