from importlib.util import module_from_spec, spec_from_file_location
from io import BytesIO
from pathlib import Path
from types import SimpleNamespace
import subprocess

import etrace

from tests.trace_builder import (
    etrace_arch,
    etrace_context,
    etrace_context_gap,
    etrace_discontinuity,
    etrace_exec32,
    etrace_info,
    etrace_status,
    etrace_tb_def,
    etrace_tb_exec,
)


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


def test_python_decoder_reads_discontinuity_record():
    decoder = etrace.etrace(
        BytesIO(
            etrace_discontinuity(
                from_pc=0x1004,
                to_pc=0x2000,
                kind=etrace.etrace.DISCONTINUITY_EXCEPTION,
                flags=5,
                unit_id=3,
            )
        )
    )

    record = decoder.stepf()

    assert record.hdr.type == decoder.TYPE_DISCONTINUITY
    assert record.hdr.unit_id == 3
    assert record.all.discontinuity.from_pc == 0x1004
    assert record.all.discontinuity.to_pc == 0x2000
    assert record.all.discontinuity.kind == decoder.DISCONTINUITY_EXCEPTION
    assert record.all.discontinuity.flags == 5
    assert decoder.type_to_name(record.hdr.type) == "discontinuity"


def test_python_decoder_reads_status_record():
    decoder = etrace.etrace(
        BytesIO(
            etrace_status(
                unresolved_tb_exits=1,
                unresolved_discontinuities=2,
                unresolved_vcpu_exits=3,
                output_errors=4,
                discontinuity_pc_mismatches=5,
            )
        )
    )

    record = decoder.stepf()

    assert record.hdr.type == decoder.TYPE_STATUS
    assert record.all.status.unresolved_tb_exits == 1
    assert record.all.status.unresolved_discontinuities == 2
    assert record.all.status.unresolved_vcpu_exits == 3
    assert record.all.status.output_errors == 4
    assert record.all.status.discontinuity_pc_mismatches == 5
    assert decoder.type_to_name(record.hdr.type) == "status"


def test_python_decoder_expands_v1_tb_execution():
    decoder = etrace.etrace(
        BytesIO(
            etrace_info(major=1)
            + etrace_arch(guest_bits=64)
            + etrace_tb_def(
                tb_id=7,
                vaddr=0x100000000,
                insns=((0, 2), (2, 5), (7, 3)),
            )
            + etrace_tb_exec(tb_id=7, insn_count=2, context_id=0)
        )
    )

    assert decoder.stepf().hdr.type == decoder.TYPE_INFO
    assert decoder.stepf().hdr.type == decoder.TYPE_ARCH
    assert decoder.stepf().hdr.type == decoder.TYPE_TB_DEF
    execution = decoder.stepf()

    assert execution.hdr.type == decoder.TYPE_EXEC
    assert execution._wire_type == decoder.TYPE_TB_EXEC
    assert execution._tb_execution.tb_id == 7
    assert execution.all.ex.nr == 1
    assert decoder.exec_entry(execution, 0).start == 0x100000000
    assert decoder.exec_entry(execution, 0).end == 0x100000007


def test_python_decoder_reads_context_and_gap():
    decoder = etrace.etrace(
        BytesIO(
            etrace_context(context_id=3, address_space_id=0x123000)
            + etrace_context_gap(
                sequence=4,
                from_context_id=3,
                to_context_id=0,
                filtered_execs=5,
            )
        )
    )

    context = decoder.stepf()
    gap = decoder.stepf()

    assert context.hdr.type == decoder.TYPE_CONTEXT
    assert context.all.context.context_id == 3
    assert context.all.context.address_space_id == 0x123000
    assert gap.hdr.type == decoder.TYPE_CONTEXT_GAP
    assert gap.all.context_gap.sequence == 4
    assert gap.all.context_gap.filtered_execs == 5
    assert decoder.type_to_name(context.hdr.type) == "context"
    assert decoder.type_to_name(gap.hdr.type) == "context_gap"


def test_viewer_advances_after_last_execution_entry():
    viewer_module = load_viewer()

    class TraceReader:
        TYPE_EXEC = 1

        def stepf(self):
            return None

    entry = SimpleNamespace(start=0x1000, end=0x1004)
    record = SimpleNamespace(
        hdr=SimpleNamespace(type=TraceReader.TYPE_EXEC),
        all=SimpleNamespace(ex=SimpleNamespace(nr=1, ex32=[entry])),
    )
    viewer = viewer_module.traceview.__new__(viewer_module.traceview)
    viewer.e = TraceReader()
    viewer.record = record
    viewer.record_idx = 0
    viewer.record_pos = entry.start

    assert viewer.step_record(1) is None
    assert viewer.record is None
