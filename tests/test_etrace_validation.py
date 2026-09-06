import pytest

from tests.trace_builder import (
    ETRACE_INFO_F_FINAL_STATUS,
    ETRACE_INFO_F_CONTEXT,
    ETRACE_INFO_F_FILTERED,
    ETRACE_TYPE_CONTEXT,
    ETRACE_TYPE_DISCONTINUITY,
    ETRACE_TYPE_STATUS,
    ETRACE_TYPE_TB,
    ETRACE_TYPE_TB_DEF,
    ETRACE_TYPE_TB_EXEC,
    etrace_discontinuity,
    etrace_context,
    etrace_context_gap,
    etrace_info,
    etrace_old_event,
    etrace_packet,
    etrace_status,
    etrace_status_v1,
    etrace_tb,
    etrace_tb_def,
    etrace_tb_exec,
)


def test_etrace_accepts_successful_final_status(run_etrace, tmp_path):
    trace = tmp_path / "complete.etrace"
    output = tmp_path / "complete.txt"
    trace.write_bytes(
        etrace_info(attributes=ETRACE_INFO_F_FINAL_STATUS)
        + etrace_status(discontinuity_pc_mismatches=2, extension=b"future")
    )

    result = run_etrace("--trace", trace, "--trace-output", output)

    assert result.returncode == 0
    assert "complete=1" in output.read_text(encoding="ascii")
    assert "discontinuity-pc-mismatches=2" in output.read_text(encoding="ascii")


def test_etrace_rejects_missing_final_status(run_etrace, tmp_path):
    trace = tmp_path / "missing-status.etrace"
    trace.write_bytes(etrace_info(attributes=ETRACE_INFO_F_FINAL_STATUS))

    result = run_etrace("--trace", trace, "--trace-output", "none")

    assert result.returncode != 0
    assert "missing its final producer status" in result.stderr


@pytest.mark.parametrize(
    ("counter", "diagnostic"),
    [
        ("unresolved_tb_exits", "unresolved-tb=3"),
        ("unresolved_discontinuities", "unresolved-discontinuity=3"),
        ("unresolved_vcpu_exits", "unresolved-vcpu=3"),
        ("output_errors", "write-errors=3"),
    ],
)
def test_etrace_rejects_producer_failure(
    run_etrace, tmp_path, counter, diagnostic
):
    trace = tmp_path / f"producer-failure-{counter}.etrace"
    trace.write_bytes(
        etrace_info(attributes=ETRACE_INFO_F_FINAL_STATUS)
        + etrace_status(**{counter: 3})
    )

    result = run_etrace("--trace", trace, "--trace-output", "none")

    assert result.returncode != 0
    assert "producer reported invalid execution data" in result.stderr
    assert diagnostic in result.stderr


def test_etrace_rejects_incomplete_status(run_etrace, tmp_path):
    trace = tmp_path / "incomplete-status.etrace"
    trace.write_bytes(etrace_status(flags=0))

    result = run_etrace("--trace", trace, "--trace-output", "none")

    assert result.returncode != 0
    assert "producer reported invalid execution data" in result.stderr


@pytest.mark.parametrize("counter", ["context_errors", "mapping_errors"])
def test_etrace_rejects_v1_producer_failure(run_etrace, tmp_path, counter):
    trace = tmp_path / f"v1-producer-failure-{counter}.etrace"
    trace.write_bytes(
        etrace_info(major=1, attributes=ETRACE_INFO_F_FINAL_STATUS)
        + etrace_status_v1(**{counter: 2})
    )

    result = run_etrace("--trace", trace, "--trace-output", "none")

    assert result.returncode != 0
    assert "producer reported invalid execution data" in result.stderr
    assert f"{counter.replace('_', '-')}=2" in result.stderr


def test_etrace_requires_extended_v1_status(run_etrace, tmp_path):
    trace = tmp_path / "short-v1-status.etrace"
    trace.write_bytes(
        etrace_info(major=1, attributes=ETRACE_INFO_F_FINAL_STATUS)
        + etrace_status()
    )

    result = run_etrace("--trace", trace, "--trace-output", "none")

    assert result.returncode != 0
    assert "short version 1 status payload" in result.stderr


def test_etrace_reports_v1_status_counters(run_etrace, tmp_path):
    trace = tmp_path / "v1-status.etrace"
    output = tmp_path / "v1-status.txt"
    trace.write_bytes(
        etrace_info(major=1, attributes=ETRACE_INFO_F_FINAL_STATUS)
        + etrace_status_v1(filtered_execs=7)
    )

    result = run_etrace("--trace", trace, "--trace-output", output)

    assert result.returncode == 0
    assert "S1 filtered-exec=7 context-errors=0 mapping-errors=0" in (
        output.read_text(encoding="ascii")
    )


def test_etrace_rejects_record_after_final_status(run_etrace, tmp_path):
    trace = tmp_path / "record-after-status.etrace"
    trace.write_bytes(etrace_status() + etrace_info())

    result = run_etrace("--trace", trace, "--trace-output", "none")

    assert result.returncode != 0
    assert "record after final status" in result.stderr


def test_etrace_rejects_short_status(run_etrace, tmp_path):
    trace = tmp_path / "short-status.etrace"
    trace.write_bytes(etrace_packet(ETRACE_TYPE_STATUS, bytes(47)))

    result = run_etrace("--trace", trace, "--trace-output", "none")

    assert result.returncode != 0
    assert "short status payload" in result.stderr


def test_etrace_decodes_discontinuity(run_etrace, tmp_path):
    trace = tmp_path / "discontinuity.etrace"
    output = tmp_path / "discontinuity.txt"
    trace.write_bytes(
        etrace_discontinuity(
            from_pc=0x1004,
            to_pc=0x2000,
            kind=2,
            flags=3,
            unit_id=7,
            extension=b"future",
        )
    )

    result = run_etrace("--trace", trace, "--trace-output", output)

    assert result.returncode == 0
    assert output.read_text(encoding="ascii") == (
        "D7 exception 1004 2000 flags=3\n"
    )


def test_etrace_rejects_short_discontinuity(run_etrace, tmp_path):
    trace = tmp_path / "short-discontinuity.etrace"
    trace.write_bytes(etrace_packet(ETRACE_TYPE_DISCONTINUITY, bytes(23)))

    result = run_etrace("--trace", trace, "--trace-output", "none")

    assert result.returncode != 0
    assert "short discontinuity payload" in result.stderr


def test_etrace_rejects_unknown_discontinuity_kind(run_etrace, tmp_path):
    trace = tmp_path / "unknown-discontinuity.etrace"
    trace.write_bytes(
        etrace_discontinuity(from_pc=0x1004, to_pc=0x2000, kind=4)
    )

    result = run_etrace("--trace", trace, "--trace-output", "none")

    assert result.returncode != 0
    assert "unknown discontinuity kind" in result.stderr


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


def test_etrace_expands_v1_tb_execution(run_etrace, tmp_path):
    trace = tmp_path / "tb-exec.etrace"
    output = tmp_path / "tb-exec.txt"
    trace.write_bytes(
        etrace_info(major=1)
        + etrace_context(context_id=3, pc=0x1000, unit_id=4)
        + etrace_tb_def(
            tb_id=7,
            vaddr=0x1000,
            context_id=3,
            insns=((0, 2), (2, 5), (7, 3)),
        )
        + etrace_tb_exec(
            tb_id=7,
            sequence=11,
            context_id=3,
            insn_count=2,
            unit_id=4,
        )
    )

    result = run_etrace("--trace", trace, "--trace-output", output)

    assert result.returncode == 0
    assert output.read_text(encoding="ascii").splitlines() == [
        "C4 id=3 pc=1000 as=0 vm=0 privilege=255 flags=0 registers=0",
        "T id=7 virt=1000-100a context=3 insns=3 mappings=0",
        "E4 1000 1007",
    ]


def test_etrace_reuses_v1_tb_definition(run_etrace, tmp_path):
    trace = tmp_path / "repeated-tb-exec.etrace"
    output = tmp_path / "repeated-tb-exec.txt"
    trace.write_bytes(
        etrace_info(major=1)
        + etrace_tb_def(tb_id=9, vaddr=0x2000, insns=((0, 4), (4, 4)))
        + etrace_tb_exec(tb_id=9, sequence=1, insn_count=1)
        + etrace_tb_exec(tb_id=9, sequence=2, insn_count=2)
    )

    result = run_etrace("--trace", trace, "--trace-output", output)

    assert result.returncode == 0
    assert output.read_text(encoding="ascii").splitlines()[-2:] == [
        "E0 2000 2004",
        "E0 2000 2008",
    ]


@pytest.mark.parametrize(
    ("records", "diagnostic"),
    [
        (etrace_tb_def(), "version 1 record without"),
        (
            etrace_info(major=1) + etrace_tb_exec(tb_id=99),
            "undefined TB ID",
        ),
        (
            etrace_info(major=1)
            + etrace_tb_def(tb_id=2)
            + etrace_tb_def(tb_id=2),
            "duplicate TB ID",
        ),
        (
            etrace_info(major=1) + etrace_tb_def(tb_id=0),
            "zero TB ID",
        ),
        (
            etrace_info(major=1)
            + etrace_tb_def(insns=((0, 4), (5, 3)), size=8),
            "non-contiguous TB instruction layout",
        ),
        (
            etrace_info(major=1)
            + etrace_tb_def(insns=((0, 4),), size=8),
            "TB instructions do not cover virtual range",
        ),
        (
            etrace_info(major=1)
            + etrace_tb_def(size=4, mappings=((0, 2, 0x8000),)),
            "TB mappings do not cover virtual range",
        ),
        (
            etrace_info(major=1)
            + etrace_tb_def(tb_id=5, insns=((0, 4),))
            + etrace_tb_exec(tb_id=5, insn_count=0),
            "invalid dispatched instruction count",
        ),
        (
            etrace_info(major=1)
            + etrace_tb_def(tb_id=5, insns=((0, 4),))
            + etrace_tb_exec(tb_id=5, insn_count=2),
            "invalid dispatched instruction count",
        ),
        (
            etrace_info(major=1)
            + etrace_packet(ETRACE_TYPE_TB_DEF, bytes(47)),
            "short TB definition payload",
        ),
        (
            etrace_info(major=1)
            + etrace_packet(ETRACE_TYPE_TB_EXEC, bytes(39)),
            "short TB execution payload",
        ),
        (
            etrace_info(major=1)
            + etrace_tb_def(size=4, code=b"\x00"),
            "partial TB code image",
        ),
        (
            etrace_info(major=1)
            + etrace_tb_def(
                size=4,
                mappings=((0, 2, 0x8000), (3, 1, 0x9000)),
            ),
            "non-contiguous TB mapping layout",
        ),
    ],
)
def test_etrace_rejects_invalid_v1_tb_stream(
    run_etrace, tmp_path, records, diagnostic
):
    trace = tmp_path / "invalid-tb-stream.etrace"
    trace.write_bytes(records)

    result = run_etrace("--trace", trace, "--trace-output", "none")

    assert result.returncode != 0
    assert diagnostic in result.stderr


def test_etrace_decodes_context_registers_and_gap(run_etrace, tmp_path):
    trace = tmp_path / "context-gap.etrace"
    output = tmp_path / "context-gap.txt"
    trace.write_bytes(
        etrace_info(
            major=1,
            attributes=ETRACE_INFO_F_CONTEXT | ETRACE_INFO_F_FILTERED,
        )
        + etrace_context(
            context_id=3,
            pc=0x1000,
            address_space_id=0x123000,
            state_hash=0x45,
            flags=3,
            architecture=62,
            privilege=0,
            registers=(("cr3", b"\x00\x30\x12\x00\x00\x00\x00\x00", 0),),
            unit_id=2,
        )
        + etrace_context(context_id=4, pc=0x2000, unit_id=2)
        + etrace_context_gap(
            sequence=9,
            from_context_id=3,
            to_context_id=4,
            filtered_execs=17,
            unit_id=2,
        )
    )

    result = run_etrace("--trace", trace, "--trace-output", output)

    assert result.returncode == 0
    assert output.read_text(encoding="ascii").splitlines() == [
        "C2 id=3 pc=1000 as=123000 vm=0 privilege=0 flags=3 registers=1 "
        "cr3=0x0000000000123000",
        "C2 id=4 pc=2000 as=0 vm=0 privilege=255 flags=0 registers=0",
        "G2 sequence=9 from=3 to=4 filtered=17 reason=1 flags=0",
    ]


def test_etrace_displays_all_tb_mapping_segments(run_etrace, tmp_path):
    trace = tmp_path / "tb-mappings.etrace"
    output = tmp_path / "tb-mappings.txt"
    trace.write_bytes(
        etrace_info(major=1)
        + etrace_tb_def(
            tb_id=4,
            vaddr=0x1000,
            size=8,
            insns=((0, 4), (4, 4)),
            mappings=((0, 4, 0x8000), (4, 4, 0xA000)),
        )
    )

    result = run_etrace("--trace", trace, "--trace-output", output)

    assert result.returncode == 0
    assert output.read_text(encoding="ascii").strip() == (
        "T id=4 virt=1000-1008 context=0 insns=2 mappings=2 "
        "map=1000-1004:8000 map=1004-1008:a000"
    )


@pytest.mark.parametrize(
    ("records", "diagnostic"),
    [
        (etrace_context(), "version 1 record without"),
        (etrace_info(major=1) + etrace_context(context_id=0), "zero context ID"),
        (
            etrace_info(major=1)
            + etrace_context(context_id=2)
            + etrace_context(context_id=2),
            "duplicate context ID",
        ),
        (
            etrace_info(major=1)
            + etrace_context(registers=(("cr3", b"", 0),)),
            "context register exceeds payload",
        ),
        (
            etrace_info(major=1)
            + etrace_context(registers=(("bad\0name", b"\x01", 0),)),
            "context register name contains NUL",
        ),
        (
            etrace_info(major=1)
            + etrace_tb_def(tb_id=3)
            + etrace_tb_exec(tb_id=3, context_id=7),
            "undefined context ID",
        ),
        (
            etrace_info(major=1) + etrace_context_gap(),
            "context gap in an unfiltered trace",
        ),
        (
            etrace_info(major=1, attributes=ETRACE_INFO_F_FILTERED)
            + etrace_context_gap(reason=2),
            "unknown context gap reason",
        ),
        (
            etrace_info(major=1, attributes=ETRACE_INFO_F_FILTERED)
            + etrace_context_gap(filtered_execs=0),
            "empty context gap",
        ),
        (
            etrace_info(major=1, attributes=ETRACE_INFO_F_FILTERED)
            + etrace_context_gap(from_context_id=99),
            "undefined source context ID",
        ),
        (
            etrace_info(major=1)
            + etrace_packet(ETRACE_TYPE_CONTEXT, bytes(47)),
            "short context payload",
        ),
    ],
)
def test_etrace_rejects_invalid_context_stream(
    run_etrace, tmp_path, records, diagnostic
):
    trace = tmp_path / "invalid-context.etrace"
    trace.write_bytes(records)

    result = run_etrace("--trace", trace, "--trace-output", "none")

    assert result.returncode != 0
    assert diagnostic in result.stderr


def test_etrace_rejects_unknown_major_version(run_etrace, tmp_path):
    trace = tmp_path / "future.etrace"
    trace.write_bytes(etrace_info(major=2))

    result = run_etrace("--trace", trace, "--trace-output", "none")

    assert result.returncode != 0
    assert "only supports versions through 1.x" in result.stderr


def test_etrace_rejects_nonconsecutive_vcpu_sequence(run_etrace, tmp_path):
    trace = tmp_path / "sequence-gap.etrace"
    trace.write_bytes(
        etrace_info(major=1)
        + etrace_tb_def(tb_id=1)
        + etrace_tb_exec(tb_id=1, sequence=5, unit_id=2)
        + etrace_tb_exec(tb_id=1, sequence=7, unit_id=2)
    )

    result = run_etrace("--trace", trace, "--trace-output", "none")

    assert result.returncode != 0
    assert "non-consecutive per-vCPU sequence" in result.stderr


def test_etrace_tracks_sequences_independently_per_vcpu(run_etrace, tmp_path):
    trace = tmp_path / "per-vcpu-sequence.etrace"
    trace.write_bytes(
        etrace_info(major=1)
        + etrace_tb_def(tb_id=1)
        + etrace_tb_exec(tb_id=1, sequence=5, unit_id=1)
        + etrace_tb_exec(tb_id=1, sequence=9, unit_id=2)
        + etrace_tb_exec(tb_id=1, sequence=6, unit_id=1)
        + etrace_tb_exec(tb_id=1, sequence=10, unit_id=2)
    )

    result = run_etrace("--trace", trace, "--trace-output", "none")

    assert result.returncode == 0
