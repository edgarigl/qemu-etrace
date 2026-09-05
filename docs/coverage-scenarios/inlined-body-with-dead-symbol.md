# Inlined body with a dead symbol

## Symptom

GCOV reports a function as hit while ETrace reports its retained ELF symbol as
dead. Source lines belonging to the function are nevertheless hit in both
reports.

The Xen `svm_sync_vmcb` result is a concrete example. Its source body executes
through optimized inline instances, while the retained out-of-line symbol is
not entered.

## Explanation

These results describe different events:

- symbol-entry coverage asks whether execution reached the address of the
  retained ELF symbol;
- source-body coverage asks whether any concrete machine-code instance of the
  source function executed.

Inlining can make the second true while the first remains false.

DWARF can also keep an inline range active over a shared return or epilogue
block that is reachable without entering the inline function. Treating any
executed address in that range as proof of entry creates a false positive. The
source policy therefore requires execution of the inline instance's
`DW_AT_entry_pc`, with `DW_AT_low_pc` as a conservative fallback.

## Expected policy results

| Policy | Retained symbol entered | Inline body executed | Function hit |
|---|---:|---:|---:|
| `entry` | No | Yes | No |
| `source` | No | Yes | Yes |

The regression fixture is `tests/fixtures/inline-function.c`, exercised by
`tests/test_function_coverage.py`. It checks both execution of the inline entry
and a synthetic jump directly into a later inline-attributed address.

When several retained local symbols describe the same source function, LCOV
emission deduplicates them by normalized source path, declaration line, and
function name. Their hit counts are combined using the maximum rather than a
sum.

## Safety interpretation

Preserve both reports when entry into the standalone implementation matters.
Use `source` when comparing against GCOV's source-oriented function result.
