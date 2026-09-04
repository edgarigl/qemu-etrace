import gzip

from tests.trace_builder import etrace_info


def test_etrace_gzip_input_is_decompressed(run_etrace, tmp_path):
    trace_data = etrace_info()
    trace = tmp_path / "trace.etrace.gz"
    output = tmp_path / "trace.etrace"
    trace.write_bytes(gzip.compress(trace_data))

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
