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

## Expected policy results

| Policy | Retained symbol entered | Inline body executed | Function hit |
|---|---:|---:|---:|
| `entry` | No | Yes | No |
| `source` | No | Yes | Yes |

The regression fixture is `tests/fixtures/inline-function.c`, exercised by
`tests/test_function_coverage.py`.

## Safety interpretation

Preserve both reports when entry into the standalone implementation matters.
Use `source` when comparing against GCOV's source-oriented function result.
