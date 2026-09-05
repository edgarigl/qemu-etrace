from tests.trace_builder import (
    etrace_arch,
    etrace_exec64,
    etrace_info,
    qemu_simple_header,
    qemu_simple_mapping,
)


def test_ascii_hex_trace_is_decoded(run_etrace, tmp_path):
    trace = tmp_path / "trace.hex"
    output = tmp_path / "trace.txt"
    trace.write_text("1234\nabc0\n", encoding="ascii")

    result = run_etrace(
        "--trace",
        trace,
        "--trace-in-format",
        "ascii-hex",
        "--trace-output",
        output,
    )

    assert result.returncode == 0
    assert [line.split() for line in output.read_text(encoding="ascii").splitlines()] == [
        ["Trace", "0", "1234", "-", "1238"],
        ["Trace", "0", "abc0", "-", "abc4"],
    ]


def test_none_discards_decoded_trace(run_etrace, tmp_path):
    trace = tmp_path / "trace.hex"
    trace.write_text("1234\n", encoding="ascii")

    result = run_etrace(
        "--trace",
        trace,
        "--trace-in-format",
        "ascii-hex",
        "--trace-output",
        "none",
    )

    assert result.returncode == 0
    assert result.stdout == ""


def test_etrace_passthrough_preserves_bytes(run_etrace, tmp_path):
    trace_data = etrace_info()
    trace = tmp_path / "trace.etrace"
    output = tmp_path / "copy.etrace"
    trace.write_bytes(trace_data)

    result = run_etrace(
        "--trace",
        trace,
        "--trace-in-format",
        "etrace",
        "--trace-out-format",
        "etrace",
        "--trace-output",
        output,
    )

    assert result.returncode == 0
    assert output.read_bytes() == trace_data


def test_etrace_preserves_short_unaligned_execution_range(run_etrace, tmp_path):
    trace = tmp_path / "unaligned.etrace"
    output = tmp_path / "unaligned.txt"
    trace.write_bytes(
        etrace_arch(guest_bits=64)
        + etrace_exec64(start=0x1001, end=0x1003)
    )

    result = run_etrace("--trace", trace, "--trace-output", output)

    assert result.returncode == 0
    assert output.read_text(encoding="ascii").splitlines()[-1] == "E0 1001 1003"


def test_qemu_simple_header_and_mapping_are_accepted(run_etrace, tmp_path):
    trace = tmp_path / "trace.simple"
    trace.write_bytes(qemu_simple_header() + qemu_simple_mapping(1, "ignored"))

    result = run_etrace(
        "--trace",
        trace,
        "--trace-in-format",
        "qemu-simple",
        "--trace-output",
        "none",
    )

    assert result.returncode == 0
    assert "invalid QEMU simple trace file" not in result.stderr
