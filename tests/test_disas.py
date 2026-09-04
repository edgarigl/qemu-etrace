from tests.trace_builder import etrace_arch, etrace_tb


def test_objdump_fallback_uses_trace_output(run_etrace, tmp_path):
    objdump = tmp_path / "objdump"
    objdump.write_text(
        "#!/bin/sh\n"
        "printf 'header 1\\nheader 2\\nheader 3\\nheader 4\\n'\n"
        "printf 'header 5\\nheader 6\\nheader 7\\n'\n"
        "printf 'fallback disassembly\\n'\n",
        encoding="ascii",
    )
    objdump.chmod(0o755)
    trace = tmp_path / "tb.etrace"
    trace.write_bytes(etrace_arch() + etrace_tb(guest_code=b"\x00\x01\x02\x03"))
    output = tmp_path / "trace.txt"

    result = run_etrace(
        "--trace",
        trace,
        "--trace-output",
        output,
        "--guest-machine",
        "test-machine-not-in-bfd",
        "--guest-objdump",
        objdump,
    )

    assert result.returncode == 0
    assert "fallback disassembly" in output.read_text(encoding="ascii")
    assert "fallback disassembly" not in result.stdout
