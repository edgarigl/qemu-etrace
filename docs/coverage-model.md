# Coverage model

qemu-etrace derives coverage from executed machine-code address ranges and
debug information. This differs from compiler-instrumented GCOV coverage, so
the metrics must be interpreted separately.

## Line coverage

An instrumented source line is hit when an executed address bucket maps to the
line through DWARF line information. A single address can map to several source
locations when code is inlined.

Line coverage does not imply GCC branch or MC/DC coverage. GCC measures arcs
selected from its compiler control-flow graph; qemu-etrace does not reconstruct
those counters.

## Function coverage

`--function-hit-policy=entry` is the default. It counts a function when the
first address bucket of its retained ELF symbol executes. This answers whether
the out-of-line machine-code function was entered.

`--function-hit-policy=source` runs `addr2line -i` over executed addresses and
attributes each address to every function in its inline stack. It reports the
maximum observed address count as `FNDA` for each matching retained ELF
function. This answers whether code originating from that source function was
executed, including an inlined instance.

The source count is a hit-oriented approximation, not an exact call count. The
maximum prevents every instruction in one invocation from being added as a
separate call. Functions with no retained ELF symbol are not currently added to
the function denominator, even when an inline-only instance is visible in
DWARF.

Generate separate reports when both facts matter:

```sh
qemu-etrace ... --function-hit-policy entry  --coverage-output entry.info
qemu-etrace ... --function-hit-policy source --coverage-output source.info
```

The distinction should remain visible in safety analysis. A source-body hit
does not prove that the retained out-of-line symbol was entered.

## Known sources of disagreement

- Inline functions and compiler-generated clones can execute without entering
  the corresponding retained symbol.
- Early boot code can execute at temporary physical addresses while ELF and
  DWARF data describe final virtual addresses.
- A synchronous exception can terminate a QEMU translation block before its
  final instruction, while TB-level tracing records the complete range.
- Coverage storage currently uses four-byte address buckets. This is exact for
  fixed-width four-byte instruction sets but approximate for variable-length
  instruction sets such as x86.
- Several source locations can share one address, particularly around inline
  call sites, macros, and adjacent line-table sequences.

See `docs/coverage-scenarios/` for worked examples and regression references.
