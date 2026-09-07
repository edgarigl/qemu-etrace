def test_help_lists_trace_and_coverage_formats(run_etrace):
    result = run_etrace("--help")

    assert result.returncode == 0
    assert "Supported trace formats:" in result.stdout
    assert "qemu-simple" in result.stdout
    assert "Supported coverage formats:" in result.stdout
    assert "lcov" in result.stdout
    assert "--function-hit-policy" in result.stdout
    assert "--coverage-inventory" in result.stdout
    assert "--auto-map" in result.stdout


def test_trace_argument_is_required(run_etrace):
    result = run_etrace()

    assert result.returncode != 0
    assert "No tracefile selected" in result.stderr


def test_coverage_inventory_requires_elf_and_lcov(run_etrace, tmp_path):
    trace = tmp_path / "empty.etrace"
    trace.write_bytes(b"")

    result = run_etrace(
        "--trace",
        trace,
        "--coverage-format",
        "lcov",
        "--coverage-output",
        tmp_path / "coverage.info",
        "--coverage-inventory",
        tmp_path / "inventory.jsonl",
    )

    assert result.returncode != 0
    assert "Coverage inventory requires --elf" in result.stderr


def test_auto_map_requires_elf(run_etrace, tmp_path):
    trace = tmp_path / "empty.etrace"
    trace.write_bytes(b"")

    result = run_etrace("--trace", trace, "--auto-map")

    assert result.returncode != 0
    assert "Automatic mapping requires an ELF" in result.stderr


def test_unresolved_limit_must_be_positive(run_etrace, tmp_path):
    trace = tmp_path / "empty.etrace"
    trace.write_bytes(b"")

    result = run_etrace(
        "--trace", trace, "--unresolved-limit", "0"
    )

    assert result.returncode != 0
    assert "Invalid unresolved limit" in result.stderr
