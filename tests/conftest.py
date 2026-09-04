from pathlib import Path
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / "qemu-etrace"


@pytest.fixture
def run_etrace():
    if not BINARY.is_file():
        pytest.fail("qemu-etrace is not built; run 'make qemu-etrace'")

    def run(*args):
        return subprocess.run(
            [str(BINARY), *(str(arg) for arg in args)],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )

    return run
