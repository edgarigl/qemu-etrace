from tests.trace_builder import (
    ETRACE_TYPE_TB,
    etrace_info,
    etrace_old_event,
    etrace_packet,
    etrace_tb,
)


def test_etrace_decodes_legacy_event_layout(run_etrace, tmp_path):
    trace = tmp_path / "legacy-event.etrace"
    output = tmp_path / "legacy-event.txt"
    trace.write_bytes(
        etrace_old_event(
            time=17,
            value=99,
            unit_id=3,
            device="timer",
            event="tick",
        )
    )

    result = run_etrace("--trace", trace, "--trace-output", output)

    assert result.returncode == 0
    assert output.read_text(encoding="ascii") == "EV 17 3 timer.tick 99\n"


def test_etrace_rejects_code_outside_tb_payload(run_etrace, tmp_path):
    valid_tb = etrace_tb(guest_code=b"\x00\x01\x02\x03")
    short_tb = valid_tb[:-4]
    payload = short_tb[8:]
    trace = tmp_path / "short-tb.etrace"
    trace.write_bytes(etrace_packet(ETRACE_TYPE_TB, payload))

    result = run_etrace("--trace", trace, "--trace-output", "none")

    assert result.returncode != 0
    assert "translation block code exceeds payload" in result.stderr


def test_etrace_rejects_truncated_payload(run_etrace, tmp_path):
    trace = tmp_path / "truncated.etrace"
    trace.write_bytes(etrace_info()[:-1])

    result = run_etrace("--trace", trace, "--trace-output", "none")

    assert result.returncode != 0
    assert "Unexpected end of ETrace payload" in result.stderr
