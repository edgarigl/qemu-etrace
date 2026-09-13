# GCC return origins before CFG construction

The final-RTL audit in [gcc-provenance.md](gcc-provenance.md) verifies machine
return witnesses but does not prove their source origin. This follow-up tests
whether earlier GCC diagnostics can supply the missing source evidence.
It adds only research fixtures and tests; it does not change analyzer inputs
or coverage policy and does not use GCOV instrumentation.

## Result

`-fdump-tree-gimple-lineno` preserves distinct return locations in these
fixtures, including a macro-expanded return and two returns on one source
line. `-fdump-tree-cfg-lineno` is already too late for that inventory: GCC has
merged returns or removed a dead path before writing it. Final RTL cannot
recover the lost origin distinction by counting machine returns.

The results below hold for the tested x86-64 GCC 13.3 and 14.2 builds at `-O2
-g`, both with direct returns and with external return thunks. Numbers count
return statements in each dump, not executions or proven source origins.

| Fixture | Early GIMPLE | Early CFG | Final machine returns | Interpretation |
|---|---:|---:|---:|---|
| Terminal value return | 1 | 1 | 1 | Possible single-origin premise; still requires source/control-flow validation |
| Folded equal expressions | 2 | 1 | 1 | Shared exit does not select a source return |
| Branchless choice | 2 | 1 | 1 | Identical PC sequences can represent different source paths |
| Macro-expanded return | 2 | 1 | 1 | Searching the unpreprocessed function for `return` misses an origin |
| Explicit void return plus fallthrough | 1 | 1 | 1 | One explicit return does not account for all normal exits |
| Discarded nonvoid result plus fallthrough | 1 | 2 | 2 | Implicit exit appears only after early GIMPLE |
| Constant-dead return | 2 | 1 | 1 | An inventory is not a reachability proof |
| Two returns on one line | 2 | 1 | 1 | Keep distinct records and columns; do not deduplicate by line |

GIMPLE return locations can identify the returned expression rather than the
`return` keyword. Retain the complete reported coordinate; these dumps are
not an AST or a compiler-stable source-origin interface. The test's extractor
is deliberately restricted to its fixed fixtures, not an arbitrary-C parser.

## The implicit-exit counterexample

```c
void explicit_and_implicit(int x)
{
    if (x)
        return;
}
```

Early GIMPLE contains one located `return;`, followed by the false-path label
and the end of the function. The CFG dump has one unlocated return after
merging the explicit and implicit exits. Both final machine paths are the
same single return instruction (or return-thunk jump).

Real qemu-x86_64 runs with `x=0` and `x=1` execute identical PCs within this
function. Only `x=1` takes the explicit source return. Thus even the rule
"one early-GIMPLE return plus a validated machine-return witness" would
create a false source hit. Full PC sequences, not just epilogue addresses,
are insufficient to distinguish these two source paths in this example.

The nonvoid fixture also falls through, but its caller explicitly discards
the result. This is not the undefined case of using a missing return value
(C11 6.9.1 paragraph 12). GCC retains two distinct machine exits here; both
are exercised. Observing an arbitrary exit still cannot credit the one
explicit return. This also rules out treating all nonvoid exits as explicit
source returns without checking the function's control flow.

The branchless-choice fixture supplies another real identical-PC comparison,
with two explicit source returns. Across two compilers and two return
mechanisms, eight retained QEMU runs check these boundaries. They are
user-mode fixture runs, not Xen IOCHK observations.

## Reproduce and retain evidence

Build qemu-etrace normally. The experiment requires pyelftools, the installed
`x86_64-linux-gnu-gcc-13` and/or `x86_64-linux-gnu-gcc-14` compilers, and an
x86 GNU objdump. Runtime checks additionally require qemu-x86_64 supporting
`-one-insn-per-tb`. Missing optional tools cause the corresponding tests to
skip; a skipped runtime check is not an execution result.

Use a new disposable directory: pytest clears an existing `--basetemp`.

```sh
python3 -m pytest -q tests/test_gcc_return_origins.py \
    --basetemp=/tmp/etrace-return-origin-evidence
```

Each compiler/return-mechanism directory retains:

- `origins-summary.json`: exact commands, compiler version, source hashes,
  dump return coordinates, full machine audits, artifact hashes, and
  code-identity results;
- `diagnostic/`: preprocessed input, early/optimized dumps, final RTL,
  annotated assembly/listing, object, and linked executable;
- `plain/`: object and executable built without diagnostics;
- `runtime-summary.json` and `qemu-{0,1}.log`: exact executable identity,
  QEMU version/commands, observed function PCs, and process exit status.

Every executable section and code relocation matches between diagnostic and
plain builds. Debug metadata need not be byte-identical. Each real run is
matched to its own diagnostic ELF, not to a different build's addresses.
The machine audit and experiment records retain `source_association:
unresolved` and `coverage_candidate: false` throughout.

## Next compiler experiment

Add `-fdump-tree-gimple-lineno` to the selected Xen translation unit's
diagnostic build, alongside the existing CFG/RTL/assembly artifacts. Keep the
normal optimization flags and verify executable bytes and relocations against
a plain control build. No `-fprofile-arcs`, `-ftest-coverage`, GCNO, or GCDA
input is needed. Normal address/DWARF coverage still needs no GCC dumps.

For a conservative single-origin rule, investigate all of the following:

1. Retain the pre-CFG return coordinates from the exact compilation,
   including macro-expanded returns and multiple records at one coordinate.
2. Establish that every supported normal source exit passes through the
   proposed return. Account for fallthrough explicitly; a return count or
   the presence of a source location on a merged CFG exit is not this proof.
3. Reject unsupported control flow, inline assembly, ambiguous source
   identity, and source-to-final-function transformations. Do not extend
   the narrow return witness to tail calls or inlined/cloned bodies by
   proximity or name alone.
4. Require the verified final machine-return witness from the matching
   image/context and observation interval. Keep dispatch distinct from
   retirement or successful completion of the return.

The [Xen block-7 study](gcc-provenance-block7.md) already reviews a terminal
`return irq;` reached by the switch arms, not merely a count of return
keywords. Its manual premise is therefore not invalidated by the implicit
exit example, but it is not generalized by these tests either. The retained
Xen bundle lacks pre-CFG GIMPLE and a matching uninstrumented runtime trace;
both remain collection tasks. Do not reuse the instrumented count of 150 or
promote this experiment into a source-hit policy.
