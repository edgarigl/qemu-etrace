# Assembly coverage semantics

qemu-etrace derives assembly line and function coverage from three independent
sources of evidence:

- ETrace execution ranges say which linked machine-code addresses executed.
- ELF executable sections bound addresses that may be attributed to code.
- DWARF line sequences and ELF function symbols describe source attribution.

Keeping these inventories separate allows line coverage to include code that
is not enclosed by a sized symbol without treating every assembly label as a
function.

## Source lines

A normal DWARF line row applies to the half-open interval from its address to
the next row in the same line-program sequence. qemu-etrace intersects that
interval with allocated executable ELF sections. An end-sequence row closes
the preceding interval but is never itself treated as a source location.

This has two important consequences:

- execution at the start of a following function cannot inherit the preceding
  file's end-sequence row;
- a line row emitted once for an assembler macro invocation can legitimately
  cover several generated functions until the next row or end marker.

A source line is instrumented when at least one byte in one of its DWARF
intervals belongs to an executable section. Its hit count is the maximum byte
execution count in those intervals. Using the maximum prevents instruction
width, aliases, and repeated mappings of one line from multiplying its count.

Line coverage is independent of ELF symbol size. Executed EFI, trampoline, or
other assembly code can therefore contribute `DA` records even when its label
has zero size or is not typed as a function.

## Functions

LCOV `FN` records require an ELF function symbol with a defensible range and a
non-inlined DWARF source location inside that range. Leading padding or
alternative bytes do not suppress a function: qemu-etrace scans forward to the
first eligible body location for the declaration line.

An explicit nonzero ELF symbol size is preferred. A zero-sized symbol receives
an inferred range only when all of the following hold:

- BFD identifies it as an ELF function;
- its address belongs to an allocated executable section;
- a strictly greater symbol address or the section end bounds the range.

Ordinary zero-sized `STT_NOTYPE` text labels are not promoted to functions.
Equal-address aliases share execution evidence, and duplicate functions with
the same name and source file remain deduplicated in LCOV. When provisional
line mappings disagree, the emitted record uses the earliest declaration line
and maximum entry count. This keeps the LCOV function-name namespace valid
without discarding observed execution.

The default `entry` function-hit policy reads execution at the symbol address.
The `source` policy retains the existing inline-instance behavior described in
[Coverage model](coverage-model.md).

## Function inventory

Use `--coverage-inventory` with LCOV output to write one JSON object per retained
text symbol:

```sh
qemu-etrace \
    --trace trace.elog.gz \
    --elf image.elf \
    --coverage-format lcov \
    --coverage-output coverage.info \
    --coverage-inventory functions.jsonl \
    --trace-output none
```

Each object records the symbol name, hexadecimal address and size, ELF-derived
kind, binding, executable section, size provenance, selected source location
and its confidence, entry hit count, and one of these statuses:

- `emitted`: eligible for an LCOV function record;
- `deduplicated-alias`: represented by an earlier equivalent function;
- `omitted-no-source`: no eligible DWARF source location intersects the range;
- `omitted-unbounded-function`: an ELF function has no safe nonempty bound;
- `omitted-zero-sized-label`: a zero-sized text label is not an ELF function;
- `omitted-non-function`: a bounded text symbol is not an ELF function;
- `omitted-non-executable`: the symbol is outside executable ELF sections.

The inventory is diagnostic evidence, not an additional coverage format. It
allows a coverage report to state exactly which retained symbols were included
or omitted and why.

## Limits

- Several generated functions may map to the same macro invocation line when
  that is all the assembler emits. qemu-etrace reports the shared mapping; it
  does not invent distinct source lines.
- Linker-discarded sections are absent from the executable image and are not
  coverage obligations, even if residual debug rows use address zero.
- A zero-sized non-function label can contribute line coverage but cannot
  produce an `FN` record without stronger ELF metadata.
- Optimized code, inline attribution, and shared epilogues can still make
  source-level function counts differ from compiler-instrumented coverage.
- Object-code line and function coverage do not imply source branch coverage or
  MC/DC.

## Validated Xen baseline

The implementation was validated against Xen revision
`4d021b1e51c003dd7c06f4fb9c90a9df29404f34` and the retained x86 trace from
`qemu-x86_64-predefined-domain: [dt_bootargs]`. The ELF SHA-256 is
`e1e8dcb0f74ca20b380294c28abeda01da82e1e0d9713ea6488132b3c9149a64`.

The regenerated assembly-related LCOV summary is:

| Metric | Result |
|---|---:|
| Source records (`.S` plus `gen-idt.h`) | 13 |
| Hit lines | 275 |
| Mapped lines | 815 |
| Hit functions | 16 |
| Reported functions | 78 |

The complete LCOV report contains 22,800/46,450 hit lines and 3,795/6,664 hit
functions. `lcov --summary` accepts it without duplicate-function errors when
run with the expected function/line consistency warnings enabled.

The expanded line universe includes executed EFI and trampoline code that was
previously hidden by zero-sized labels. `entry.S:779` is now correctly dead;
`l3t_unlock`, `ret_from_intr`, `handle_exception`, and `trap_nop` no longer
inherit locations across end-sequence boundaries; and `common_interrupt` plus
`handle_ist_exception` have function records.

Some generated IDT entries and register-specific indirect thunks still have no
DWARF source range. They are not assigned a guessed source line. The function
inventory records them as `omitted-no-source` together with their observed
entry counts. The checked baseline and validation utility are
[`tests/fixtures/xen-assembly-validation.json`](../tests/fixtures/xen-assembly-validation.json)
and [`tests/xen_assembly_validation.py`](../tests/xen_assembly_validation.py).

The validated output hashes are recorded in the baseline. Reproduce the audit
with:

```sh
python3 -m tests.xen_assembly_validation \
    --lcov /path/to/coverage.info \
    --inventory /path/to/functions.jsonl \
    --elf /path/to/xen-syms.debug \
    --implementation 7c0d0f5 \
    --expected tests/fixtures/xen-assembly-validation.json
```
