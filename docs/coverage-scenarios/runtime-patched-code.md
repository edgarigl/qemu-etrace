# Runtime-patched code and line counts

## Symptom

A source line can have a much larger execution count than the apparently
adjacent straight-line assembly, even when the producer reports no unresolved
execution ranges.

The Xen `svm_asm_do_resume` path provides a concrete example. One QEMU 11 MCE
qtest produced:

```text
DA:108,22      # vmrun
DA:110,22      # SAVE_ALL
DA:112,352     # GET_CURRENT and runtime alternative region
DA:161,22      # stgi
```

The factor is exact:

```text
352 = 16 * 22
```

## Static and runtime code differ

The linked ELF shows `GET_CURRENT` followed by a large NOP-filled alternatives
area:

```text
ffff82d0402a4b20  GET_CURRENT instructions
ffff82d0402a4b2c  static NOP padding begins
ffff82d0402a4b97  STGI
```

At runtime Xen enables an alternative in this interval:

```asm
ALTERNATIVE "", DO_OVERWRITE_RSB, X86_FEATURE_SC_RSB_HVM
```

`DO_OVERWRITE_RSB` contains a 16-iteration loop with two calls per iteration:

```asm
mov $16, %ecx
...
sub $1, %ecx
jnz ...fill_rsb_loop
```

The static ELF therefore describes NOPs at addresses where QEMU executes
runtime-patched branch and call instructions.

## Trace evidence

The exact `TYPE_EXEC` ranges around the patched loop were:

| Range | Count | Interpretation |
|---|---:|---|
| `0xffff82d0402a4aa8-0xffff82d0402a4aab` | 22 | `VMRUN` |
| `0xffff82d0402a4aab-0xffff82d0402a4b4f` | 22 | Initial path into the alternative |
| `0xffff82d0402a4b4a-0xffff82d0402a4b4f` | 330 | Fifteen loop-back executions per VM exit |
| `0xffff82d0402a4b50-0xffff82d0402a4b55` | 352 | Sixteen executions per VM exit |
| `0xffff82d0402a4b56-0xffff82d0402a4b5b` | 352 | Sixteen executions per VM exit |
| `0xffff82d0402a4b5b-0xffff82d0402a4b6c` | 22 | Loop completion path |
| `0xffff82d0402a4b75-0xffff82d0402a4b9a` | 22 | Path through `STGI` |

The first loop range executes once as part of the initial range and fifteen
more times through its loop-back TB:

```text
22 + 330 = 352
```

The trace therefore represents the expected runtime control flow rather than
duplicated execution evidence.

## DWARF attribution

The ELF line table has no new row between the `GET_CURRENT` row at line 112
and the `STGI` row at line 161. All runtime alternative addresses consequently
inherit line 112.

qemu-etrace reports the maximum observed byte count for each source line. A
byte in the patched loop executes 352 times, so `DA:112,352` follows the
documented aggregation policy. It is not an invocation count for the
three-instruction `GET_CURRENT` macro alone.

## Expected handling

- Treat the line as covered.
- Preserve the observed count; do not force it to match surrounding lines.
- Do not use a static straight-line invariant across an alternatives region.
- For this SVM configuration, validate `line 108 == line 110 == line 161`.
- Require `line 112 >= line 110` generally.
- When `X86_FEATURE_SC_RSB_HVM` selects the shown replacement and no other path
  changes the interval, expect `line 112 == 16 * line 110`.

Changing global LCOV aggregation to hide the loop would under-report genuine
multi-path and repeated execution elsewhere.

## Branch-coverage consequence

Static ELF bytes are insufficient for branch classification in a patched
alternatives region. Object branch coverage must either:

- use translated instruction bytes and a runtime code identity supplied by
  the QEMU plugin;
- consume explicit alternative metadata; or
- mark the affected branch observations unresolved.

It must not decode the static NOP bytes and claim that the runtime interval has
no branches.

## Registered x86 alternative calls

An x86-64 ELF may publish alternative-call sites through the boundary symbols
`__alt_call_sites_start` and `__alt_call_sites_end`. The table contains signed
32-bit offsets relative to each table entry. qemu-etrace accepts the metadata
only when every resulting six-byte range is executable and begins with the
linked indirect-call encoding `ff 15 disp32`.

For a TB already owned by a trusted image mapping, a registered call
instruction can match one of these runtime forms:

- the original indirect call from the ELF;
- `2e e8 disp32`, when the direct destination lies in an executable section of
  the selected ELF, including a destination immediately after `endbr64`;
- the six-byte poison sequence `0f 0b 0f 0b 0f 0b`, observed as either the
  complete range or its individual two-byte `ud2` instructions.

All bytes outside registered slots retain exact instruction validation. An
unknown slot encoding or an out-of-image direct target stops validation at
that instruction and leaves the rest of the execution unresolved. Recognized
patches do not create or extend image mappings. ELFs without both boundary
symbols retain ordinary byte matching, while malformed tables are rejected.

## Xen x86 alternatives

For Xen x86-64 ELFs, qemu-etrace also reads the packed 14-byte records between
`__alt_instructions` and `__alt_instructions_end`. Each origin and replacement
address is a signed 32-bit offset relative to its own field. The table is
accepted only when every original span is executable, every nonempty
replacement is present in the ELF, shared origins have equal original and
padding lengths, and the registered spans do not overlap.

An alternative with an empty replacement can replace its complete original
plus padding span with Xen's ideal NOPs. An unselected alternative can also
retain its original bytes while Xen optimizes its build-time NOP padding.
qemu-etrace accepts the P6 and K8 NOP sequences generated in chunks of up to
nine bytes for both states. Any non-padding original bytes must still match
the ELF exactly.

qemu-etrace validates the complete registered span before crediting any of its
runtime instructions, including when NOP encoding changes instruction
boundaries, and then resumes exact instruction validation after the span.

A partial span, an unregistered NOP, or any other byte sequence remains
unresolved. General alternatives are considered only inside an explicit or
already owned image mapping, so a patched span cannot establish or extend a
physical image mapping. Selected nonempty general replacements are not yet
accepted unless their bytes are identical to a legal unselected state.

## Safety interpretation

The result is valid dispatched-instruction evidence with imprecise source
attribution. The line-hit result is reliable, while its numeric execution
count includes the runtime mitigation loop attributed to the same DWARF line.
Reviews that depend on execution frequency should retain the trace evidence
and the active alternative configuration.

The qemu-etrace producer status for the validating run was complete with zero
unresolved TB, discontinuity, vCPU, and output-error counters.

## Regression coverage

The validating 156 MB compressed trace is retained outside the repository.
The raw range counts above provide the audit record. A future compact fixture
should combine static NOP bytes and DWARF attribution with synthetic execution
ranges matching the patched loop, without checking in the full trace.
