from importlib.util import module_from_spec, spec_from_file_location
from io import BytesIO
from pathlib import Path
import subprocess

import etrace

from tests.trace_builder import etrace_arch, etrace_exec32


ROOT = Path(__file__).resolve().parents[1]
VIEWER = ROOT / "etrace-view.py"


def load_viewer():
    spec = spec_from_file_location("etrace_view", VIEWER)
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_viewer_help_runs_with_python3():
    result = subprocess.run(
        [str(VIEWER), "--help"],
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0
    assert "--trace" in result.stdout


def test_python_decoder_reads_execution_record():
    decoder = etrace.etrace(
        BytesIO(
            etrace_arch(guest_bits=32)
            + etrace_exec32(
                start_time=10,
                duration=4,
                start=0x1000,
                end=0x1004,
            )
        )
    )

    architecture = decoder.stepf()
    execution = decoder.stepf()

    assert architecture.all.arch.guest.arch_bits == 32
    assert execution.all.ex.nr == 1
    assert execution.all.ex.ex32[0].duration == 4
    assert execution.all.ex.ex32[0].start == 0x1000
    assert execution.all.ex.ex32[0].end == 0x1004
