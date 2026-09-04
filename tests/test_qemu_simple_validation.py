from tests.trace_builder import (
    QEMU_SIMPLE_DROPPED_EVENT_ID,
    qemu_simple_event,
    qemu_simple_header,
    qemu_simple_mapping,
)


def test_qemu_simple_rejects_short_tb_event(run_etrace, tmp_path):
    trace = tmp_path / "short.simple"
    trace.write_bytes(
        qemu_simple_header()
        + qemu_simple_mapping(1, "tb_enter_exec")
        + qemu_simple_event(1)
    )

    result = run_etrace(
        "--trace",
        trace,
        "--trace-in-format",
        "qemu-simple",
        "--trace-output",
        "none",
    )

    assert result.returncode != 0
    assert "tb_enter_exec requires 3 arguments" in result.stderr


def test_qemu_simple_rejects_short_dropped_event(run_etrace, tmp_path):
    trace = tmp_path / "short-dropped.simple"
    trace.write_bytes(
        qemu_simple_header() + qemu_simple_event(QEMU_SIMPLE_DROPPED_EVENT_ID)
    )

    result = run_etrace(
        "--trace",
        trace,
        "--trace-in-format",
        "qemu-simple",
        "--trace-output",
        "none",
    )

    assert result.returncode != 0
    assert "dropped event requires 1 argument" in result.stderr
