# Coverage model

qemu-etrace derives coverage from executed machine-code address ranges and
debug information. This differs from compiler-instrumented GCOV coverage, so
the metrics must be interpreted separately.

Assembly line-sequence handling, zero-sized labels, inferred function bounds,
and function inventory diagnostics are described in
[Assembly coverage semantics](assembly-coverage.md).

Loader-selected runtime addresses can be normalized with `--address-map`
before applying this model. See [Runtime address maps](address-maps.md).

## Line coverage

An instrumented source line is hit when an executed byte address maps to the
line through DWARF line information. A single address can map to several source
locations when code is inlined.

This address-based rule is the default. `--line-hit-policy=function-entry`
also propagates each reported function's selected hit count to its resolved
DWARF subprogram declaration line. A line-table coordinate used as an `FN`
fallback is not sufficient for propagation. This opt-in policy makes verified
function-declaration lines comparable with compiler-instrumented reports while
retaining address-derived hits for all other lines. It uses the selected
`--function-hit-policy`, so `entry` propagates retained-symbol entry counts and
`source` can propagate a validated inline instance entry.

Coverage counters and DWARF locations are indexed by byte offset from the
containing ELF symbol. An execution range marks every byte in its half-open
`[start,end)` interval. This handles both fixed-width and variable-length
instruction sets without rounding either boundary. The byte-addressed arrays
use approximately four times as much memory as four-byte arrays for covered
symbols.

Line coverage does not imply GCC branch or MC/DC coverage. GCC measures arcs
selected from its compiler control-flow graph; qemu-etrace does not reconstruct
those counters.

## Attribution diagnostic

Add `--coverage-attribution FILE` to an ELF-backed LCOV run to export the
DWARF line-table evidence behind address-based coverage:

```sh
qemu-etrace --trace run.etrace --elf program.elf --trace-output none \
    --coverage-format lcov --coverage-output coverage.info \
    --coverage-attribution attribution.jsonl
```

This optional output requires neither GCOV runtime instrumentation nor GCC
build dumps. It does not change the coverage policies or LCOV output. Keep
the exact ELF/debug information used for the trace; addresses and debug
coordinates from an instrumented build must not be applied to another build.
Use distinct paths for the diagnostic and other inputs/outputs.

Each JSON Lines record describes one source location and one half-open span
with a constant executable status and byte-address hit count. For example:

```json
{"version":1,"kind":"dwarf-line","source":"/src/example.c","line":10,"column":3,"discriminator":7,"is_stmt":true,"range_start":"0x401000","range_end":"0x401003","start":"0x401000","end":"0x401002","executable":true,"hits":4,"excluded":false}
```

- `source`, `line`, `column`, `discriminator`, and `is_stmt` preserve the
  location metadata, using the analyzer's normalized source path. Zero line
  or column values retain DWARF's unspecified coordinates. `is_stmt` is the
  DWARF statement marker, not proof that a source statement executed.
- `range_start` and `range_end` identify the original attribution interval
  built from the DWARF rows and sequence boundaries. All source aliases at
  an equal address are retained as separate records, even when they share
  a line but differ in column, discriminator, or statement marker.
- `start` and `end` identify a span inside that interval. Addresses are hex
  strings in linked ELF coordinates, after any trace address normalization.
  A partially observed interval therefore has separate hit and missed spans.
- `executable` indicates membership in an allocated executable ELF section.
  Nonexecutable intervals, including stale ranges for discarded sections,
  remain visible with zero hits but do not contribute LCOV lines.
- `hits` is the accumulated execution-range count at each byte in the span.
  Do not sum the records to obtain line, instruction, or function counts:
  aliases duplicate evidence, and every byte of an instruction is credited.
  Address-based LCOV takes the maximum count across a line's executable ranges.
- `excluded` indicates an exact source-file/line exclusion. Excluded evidence
  remains in this diagnostic even though LCOV omits the line.

The output is raw line-table evidence, not an inline-stack report or a list
of all source statements. It does not include declaration-line hits inferred
by `--line-hit-policy=function-entry`; use `--coverage-inventory` alongside it
to inspect function attribution. An ELF with no usable line ranges produces
an empty diagnostic. Output creation/write failures are fatal. Large images
can produce large files; collection is opt-in and scans all DWARF ranges.

A zero hit count does not identify the cause: the code may be unexecuted,
filtered from the trace, or unresolved by image matching. Conversely, an
observed range cannot disambiguate multiple source paths that the compiler
folded into the same code. In particular, a `DW_TAG_label` address alone is
not enough to credit that source label; see
[Folded source labels](coverage-scenarios/folded-source-labels.md).

The uninstrumented assembly fixture in
[`tests/test_coverage_attribution.py`](../tests/test_coverage_attribution.py)
checks equal-address aliases, partial counts, discarded code, exclusions,
output errors, and unchanged LCOV output.

## Function coverage

`--function-hit-policy=entry` is the default. It counts a function when the
first byte of its retained ELF symbol executes. This answers whether the
out-of-line machine-code function was entered.

`--function-hit-policy=source` reads inline-instance entry PCs from DWARF and
uses `addr2line -i` to attribute executed entries to every function in their
inline stacks. It reports the maximum observed instance-entry count as `FNDA`
for each matching retained ELF function. This answers whether an out-of-line or
inline instance of that source function was entered.

The source count is a hit-oriented approximation, not an exact call count. The
maximum prevents every instruction in one invocation from being added as a
separate call. Functions with no retained ELF symbol are not currently added to
the function denominator, even when an inline-only instance is visible in
DWARF. Inline instances without `DW_AT_entry_pc` use `DW_AT_low_pc`; instances
without either attribute are ignored conservatively.

An x86-64 inline instance may have several compiler-generated entry blocks in
one DWARF range list. For a covered alternate range start, the source policy
accepts it only when its initial integer comparison block is byte-equivalent
to the declared entry, its conditional branch reaches the same two successor
addresses (allowing an inverted condition), and the caller's machine CFG has
a path to it from outside that inline instance. RIP-relative, unsupported, or
ambiguous blocks remain unverified. This duplicated-block check does not
recognize source names or fixed addresses, and it never treats all range starts
as entries. Other architectures retain the declared-entry policy.

Generate separate reports when both facts matter:

```sh
qemu-etrace ... --function-hit-policy entry  --coverage-output entry.info
qemu-etrace ... --function-hit-policy source --coverage-output source.info
```

The distinction should remain visible in safety analysis. A source-body hit
does not prove that the retained out-of-line symbol was entered.

## Plugin execution ranges

The ETrace format assumes that every execution range is accurate. The upstream
QEMU plugin automatically selects the least expensive mechanism supported by
the QEMU API:

- API version 1 emits one exact half-open `[pc, pc + size)` range for every
  instruction callback;
- newer APIs delay a TB record and update per-vCPU inline progress before every
  instruction;
- the last dispatched instruction bounds the range even when an architectural
  transition has no discontinuity callback;
- discontinuity records distinguish exceptions, interrupts, and host calls
  from ordinary control flow without being required to reconstruct the
  execution prefix.

Instruction callbacks prove that QEMU dispatched an instruction, not that the
architecture retired it. A faulting instruction may have produced its callback
without completing. QEMU also documents exception paths on which the faulting
instruction is not observable through the general instruction callback. The
metric is therefore dispatched-instruction coverage, not retirement coverage.

Version 0 execution uses ordinary `TYPE_EXEC` records. With `format=v1`, the
plugin emits one `TYPE_TB_DEF` per translation and a compact `TYPE_TB_EXEC`
containing the dispatched instruction count. The reader expands that pair into
the same internal half-open execution range, so coverage accounting is shared
with version 0 and the other input formats. Discontinuity-capable builds also
emit `TYPE_DISCONTINUITY` records containing the source PC, destination PC, and
event kind. API version 1 has substantially higher callback and trace volume;
its instruction-granularity results serve as the correctness reference for the
optimized implementation.

Version 1 can associate execution with context-change records and observed
instruction mappings. A filtered trace contains explicit gap records between
retained ranges. See `etrace-v1.md` for the format and plugin options.

`--elf-context` restricts coverage for the selected ELF to an architectural
privilege level recorded by the producer. This distinguishes, for example,
an AArch64 EL2 image from code executing at EL1 at the same address. Context
selection complements address and byte validation; it does not identify an
image by itself. A matching execution at a byte-verified linked ELF address
can establish the load bias for the ELF's executable load segments. Physical
executions within those segments are then checked against their derived ELF
addresses before coverage is credited. An incomplete early context can use
that established ownership after its architecture and TB bytes are checked;
an explicitly different privilege level remains excluded.

For an image-owned TB with a runtime code change, validation proceeds by
complete instruction. Matching instructions before the first unexplained
mismatch contribute coverage; the mismatching instruction and remainder form
an unresolved execution boundary. A partially matching TB never supplies
image-ownership evidence for another TB.

With `--auto-map`, unmatched TB executions are aggregated until their code and
physical mappings can be associated with the input ELF. Resolution replays the
aggregates through the same range processor. Ambiguous or unrelated TBs are
reported but never guessed into the coverage result; exhausting the configured
pending-aggregate limit is fatal.

During ordered replay and subsequent ordered online processing, an owned,
fully dispatched TB can pass ownership to the immediately following TB on the
same vCPU and in the same nonzero execution context when its decoded final
instruction is ordinary and falls through exactly to the successor. Runtime
and linked ranges must both be contiguous and remain within one 4 KiB page,
and every successor instruction must validate against the ELF or registered
patch metadata. Discontinuities, context gaps, control-flow instructions,
partial dispatch or validation, and address or mapping conflicts break this
propagation. Observed physical mappings are bound only for the validated
successor spans. The resulting TB remains local to that context and never
becomes a whole-image mapping anchor.

`--preserve-order` replaces unresolved aggregation with a disk-backed dynamic
event journal and a second replay pass. It preserves the producer's observed
stream interleaving and per-vCPU sequence. Remaining unresolved executions are
explicit boundaries and are not connected to adjacent control flow.

Plugin traces advertise `ETRACE_INFO_F_FINAL_STATUS` and end with a
`TYPE_STATUS` record. The converter rejects a missing or incomplete final
status and any nonzero unresolved-execution or output-error counter.
Discontinuity-PC mismatches are retained as diagnostics because virtualization
transitions can legitimately report a source outside the currently pending
translation block; per-instruction progress remains authoritative for the
ordinary execution prefix. Plugin shutdown flushes every observed vCPU even
when QEMU has not invoked its vCPU-exit callback.

## Known sources of disagreement

- Inline functions and compiler-generated clones can execute without entering
  the corresponding retained symbol.
- Early boot code can execute at temporary physical addresses while ELF and
  DWARF data describe final virtual addresses.
- A faulting instruction can be dispatched without retiring or can be absent
  from the normal instruction callback on some exception paths. Discontinuity
  records keep that attempted instruction distinct from the completed prefix.
- Several source locations can share one address, particularly around inline
  call sites, macros, and adjacent line-table sequences.
- Runtime alternatives can replace ELF NOPs with loops or branches while DWARF
  continues to attribute the addresses to the preceding source line. See
  [Runtime-patched code](coverage-scenarios/runtime-patched-code.md).

See `docs/coverage-scenarios/` for worked examples and regression references.
