# Branch and MC/DC coverage plan

## Recommendation

Start by fixing execution-range accuracy in the QEMU plugin. Do not make branch classification or MC/DC depend on the current assumption that entering a translation block means its complete address range executed.

The implementation order should be:

1. add a simple instruction-granularity mode as a correctness reference and immediate workaround;
2. record exceptions, interrupts, and host calls explicitly;
3. add efficient terminal-instruction tracking to produce precise TB ranges with one inline store per TB;
4. retain per-instruction last-PC tracking as a compatibility fallback when discontinuities are unavailable;
5. derive object-code branch edges and outcomes;
6. add static branch inventories and LCOV `BRDA` output;
7. import compiler-instrumented MC/DC results;
8. investigate non-instrumenting compiler metadata as a separate compiler project.

This order fixes an existing coverage error before building a new metric on top of it.

## Current plugin behavior and defects

[`plugin/etrace-plugin.c`](../plugin/etrace-plugin.c) registers one callback at TB entry. That callback immediately writes a `TYPE_EXEC` record covering:

```text
[TB first PC, last translated instruction PC + instruction size)
```

The record describes the translated TB, not the instructions actually dispatched. [`etrace_process_exec()`](../etrace.c) subsequently increments coverage for every byte in that range. A synchronous exception before the TB's end therefore produces false-positive coverage for the undispatched tail. This is already described as a limitation in [`docs/coverage-scenarios/partial-tb-execution.md`](../docs/coverage-scenarios/partial-tb-execution.md), but it is a correctness defect for exception-sensitive coverage rather than merely a reporting inconvenience.

The present trace also has no explicit transfer or discontinuity record. A later TB at an unexpected address is visible, but the trace cannot say whether control arrived there through a branch, trap, interrupt, host call, or exception in the middle of the prior TB.

| Situation | What the plugin records today | Consequence |
|---|---|---|
| TB completes normally | Full translated range | Correct for dispatched-instruction coverage |
| Instruction in the middle traps or faults | Full translated range | Instructions after the fault are falsely marked hit |
| Last instruction traps | Full translated range | Range is plausible, but the trap is invisible |
| Interrupt occurs between TBs | Two TB ranges | The handler transition is indistinguishable from program control flow |
| Exception stops execution with no later TB | Full range only | Neither the actual stop PC nor the exception is visible |
| Direct TB chaining is enabled | A callback for every chained TB | Supported by the current upstream plugin; `-d nochain` is not required |

Synchronous faults, traps, and host calls can leave a TB before its translated end. Asynchronous interrupts are normally taken at a TB boundary, so they do not create the same false tail, but their transfer to a handler is still indistinguishable from a normal program edge in the current trace.

The improved metric should be named **dispatched-instruction coverage**. QEMU plugin instrumentation runs before an instruction completes, and a faulting instruction may not retire. Exact architectural retirement is not available from the general plugin execution callbacks. The trace must not silently call dispatch coverage retirement coverage.

## QEMU API availability

The useful APIs arrived in stages:

| QEMU release | Plugin API | Capability |
|---|---:|---|
| 8.2 | 1 | Per-instruction and TB host callbacks; sufficient for a slow instruction mode |
| 9.0 | 2 | Per-vCPU scoreboards and inline stores; sufficient for efficient last-instruction tracking |
| 9.1 | 3 | Conditional execution callbacks; useful for reducing callbacks, but not required for precise TB ranges |
| 10.2 | 5 | Discontinuity callbacks for interrupts, exceptions, and host calls |

The scoreboard and conditional-callback additions are visible in the QEMU commits [a3c2cf0b89](https://github.com/qemu/qemu/commit/a3c2cf0b891d00ef502e9902baa9fb7fe1f8e7a3) and [7de77d3788](https://github.com/qemu/qemu/commit/7de77d37880d7267a491cb32a1b2232017d1e545). The discontinuity API was added by [aac73d85d2](https://github.com/qemu/qemu/commit/aac73d85d2d6f556dbcee6041a2898cb0ef9b0e6). QEMU's [`cflow` plugin](https://github.com/qemu/qemu/blob/master/contrib/plugins/cflow.c) demonstrates the scoreboard algorithm.

Do not use `QEMU_PLUGIN_VERSION >= 5` to detect discontinuity support: QEMU 10.1 and 10.2 both use API version 5, but only 10.2 has `qemu_plugin_register_vcpu_discon_cb()`. The build must probe the selected header for that declaration and define a project feature macro.

## QEMU TB exit rules and their consequences

QEMU's TB rules make a per-instruction inline store unnecessary on the normal
fast path:

- branches and other translated control transfers terminate the TB, so a
  normally executed branch is the final translated instruction;
- asynchronous interrupts are observed between TBs and do not abandon a TB in
  its middle;
- the generated exit-request check precedes plugin TB-entry instrumentation,
  so a TB rejected before execution does not produce a TB-entry callback;
- synchronous exceptions and host calls can abandon a TB in its middle, and
  the discontinuity callback reports their source instruction as `from_pc`;
- QEMU-internal restarts such as MMIO retranslation, atomic re-execution,
  precise self-modifying-code handling, and watchpoint handling can also leave
  generated code early, but are not architectural discontinuities.

The optimized design should therefore record whether execution reached the
TB's terminal instruction rather than recording every intermediate PC. A
missing terminal marker means either that a discontinuity must resolve the
prefix or that an internal restart needs conservative handling.

The public plugin API still has no callback covering every normal and abnormal
TB exit. A future QEMU API carrying an exit reason, last guest PC, and next
guest PC would remove the remaining inference and should be pursued separately.

## Phase 1: Add an instruction-mode correctness reference

Add a plugin option:

```text
exec=tb        current fast, optimistic behavior
exec=insn      one TYPE_EXEC range per dispatched instruction
exec=precise   efficient last-dispatched TB ranges, when supported
```

Keep `exec=tb` as the initial default. In `exec=insn`, register a host execution callback for each translated instruction and emit `[pc, pc + size)`. If instruction `N` traps, callbacks for instructions `N+1...` do not run, so the false-positive tail disappears.

This mode is deliberately expensive: it adds a host callback and trace record for every instruction. Its value is that it:

- works with the oldest supported plugin API;
- gives users an immediate exception-sensitive mode;
- provides an oracle for testing the later `exec=precise` implementation;
- requires no branch decoder or trace-format change.

An instruction callback still proves dispatch rather than retirement. A faulting instruction can be absent from normal instruction callbacks on some exception paths, which the discontinuity record added later will make visible.

### Phase 1 acceptance criteria

- A complete two-instruction TB emits two one-instruction ranges.
- Simulating a trap after the first callback emits only the first range.
- Variable-width instruction sizes produce exact half-open ranges.
- Raw and gzip output remain byte-for-byte equivalent after decompression.
- API version 1, the repository's default test API, and the version 7 callback ABI all build and pass.

## Phase 2: Record discontinuities

Add a versioned packet type:

```c
struct etrace_discontinuity {
        uint64_t from_pc;
        uint64_t to_pc;
        uint32_t kind;       /* interrupt, exception, host call, unknown */
        uint32_t flags;
};
```

The ETrace header already supplies `unit_id`. Add validation, human-readable
output, Python fixture support, and forward-compatible handling before making
the plugin emit the packet.

When `qemu_plugin_register_vcpu_discon_cb()` is available, record QEMU's type,
`from_pc`, and `to_pc` exactly. The callback should also clear pending
normal-edge state so a handler's first TB is not attributed as a program
branch destination.

For exceptions and host calls, `from_pc` names the source instruction. Keep it
separate from the preceding ordinary execution range: QEMU documents that an
exception-causing instruction may not retire and may not even be observable
through a general instruction callback. The trace can later expose an explicit
policy for counting that source as attempted execution without presenting it
as retired execution.

Discontinuities solve two distinct problems:

- an early exception supplies the exact boundary needed to avoid counting the
  undispatched TB tail;
- an exception or interrupt edge cannot contaminate future branch coverage.

### Phase 2 acceptance criteria

- A middle-instruction exception records `from_pc` at the faulting instruction.
- A terminal trap remains distinct from ordinary TB completion.
- An interrupt after a completed TB records the next would-have-executed PC as
  `from_pc` and the handler PC as `to_pc`.
- A host call is not counted as a program branch.
- A handler TB cannot resolve a pending conditional branch outcome.
- A QEMU 10.1 header builds without discontinuity support; a 10.2 header enables
  it through a header feature probe.
- Unknown packet kinds and malformed lengths are rejected consistently with
  the existing validation code.
- MicroBlaze unaligned exceptions are tested for duplicate or pre-vector
  callbacks before the plugin relies on their ordering.

## Phase 3: Emit efficient precise TB ranges

For QEMU plugin API version 2 or newer, allocate a per-vCPU scoreboard with at least:

```c
struct vcpu_exec_state {
        uint64_t pending_tb_id;
        uint64_t reached_last;
};
```

Retain immutable `tb_data` objects until plugin shutdown, as the plugin already
does. Each object should contain the TB start, nominal end, stable ID, and the
instruction boundaries needed to validate a discontinuity's `from_pc`.

At translation time:

1. register the existing TB-entry host callback;
2. register one inline `STORE_U64` on only the final translated instruction,
   setting `reached_last` immediately before that instruction is dispatched.

At TB entry:

1. read the prior vCPU's pending TB and `reached_last`;
2. if `reached_last` is set, emit the prior nominal range;
3. otherwise treat the prior execution as an internal restart or unresolved
   exit, emitting only a prefix proven by a known successor instruction
   boundary;
4. install the current TB as pending and clear `reached_last` before its final
   instruction can execute.

At a discontinuity:

1. for an interrupt, flush the pending TB as complete because asynchronous
   interrupts occur at TB boundaries;
2. for an exception or host call, emit `[pending.start, from_pc)` when
   `from_pc` is a valid instruction boundary in the pending TB;
3. emit the discontinuity packet, leaving its source instruction separate;
4. clear pending normal execution and branch-edge state.

When a missing terminal marker is followed by a new TB without an intervening
discontinuity, use the new TB start only when it proves a non-overlapping prefix
of the prior TB. This covers internal restart paths without confusing a normal
backward branch: a normally dispatched terminal branch sets `reached_last`.
If the successor does not establish a safe boundary, emit an unresolved state
and a diagnostic rather than the nominal range.

Register a vCPU-exit callback to flush the last pending range. The atexit callback should verify that all initialized vCPUs were flushed before closing gzip output. Abrupt host termination remains unable to guarantee a complete trace, as it does today.

This design delays a vCPU's record by one TB. Cross-vCPU packet order can therefore differ slightly from entry order, but the existing records have zero duration and coverage processing is already keyed by `unit_id`. Add a per-vCPU sequence number before any consumer starts treating packet order as an execution timeline.

Add an information flag such as:

```c
ETRACE_INFO_F_PRECISE_EXEC_RANGES
```

It means that `TYPE_EXEC` ranges were resolved through terminal-instruction
markers, discontinuities, or conservative internal-restart boundaries. Old
readers can still consume the shorter ranges; new readers can report the
precision provenance.

For QEMU without discontinuity callbacks, and for user-mode emulation where
the system discontinuity hooks are unavailable, retain the original
per-instruction `last_dispatched_end` scoreboard algorithm as a compatibility
fallback. It costs one inline store per instruction but does not rely on an
exception event to locate the early exit.

### Why this is preferable to correction packets

Do not first emit the nominal full range and later send a packet subtracting its tail. Current coverage counters are updated online and are additive. Delaying the prior TB by one entry keeps the stream monotonic and avoids subtraction, rollback, and duplicate-source attribution problems.

### Phase 3 acceptance criteria

- Complete TBs retain their current ranges.
- Normal execution adds only one inline store per TB.
- A middle-instruction exception ends the ordinary prefix at the exception's
  `from_pc` and records the source separately.
- A last-instruction exception records the preceding prefix plus the exception,
  without counting any undispatched tail.
- The same TB executing repeatedly is resolved independently on every iteration.
- vCPU state never crosses between CPUs under MTTCG.
- The final TB on each vCPU is flushed exactly once.
- Address overflow produces a bounded range and a diagnostic.
- `exec=precise` is rejected with a clear message when built against API version 1.
- The fallback and optimized modes produce identical ordinary covered prefixes;
  exception-source attempts are compared separately.
- MMIO replay, atomic re-execution, precise SMC, and watchpoint exits never
  cause the undispatched tail to be emitted.

## Phase 4: Make precision the normal plugin path

Benchmark all three modes on representative firmware and SMP guests:

- wall-clock slowdown relative to no plugin and current `exec=tb`;
- translated code growth from one inline store per TB, plus the
  per-instruction fallback;
- raw and gzip trace sizes;
- callback count and lock contention;
- memory retained per unique translation;
- behavior during translation-cache flush and self-modifying code.

If the scoreboard path has acceptable overhead, make `exec=precise` the default for API version 2 or newer and retain `exec=tb` as an explicitly optimistic compatibility mode. Otherwise keep it opt-in, but print and record that `exec=tb` can over-report after synchronous exceptions.

Do not claim the limitation is solved until a real QEMU integration test deliberately triggers a synchronous exception in the middle of a multi-instruction TB. Unit callbacks alone verify plugin bookkeeping, not QEMU's actual callback ordering.

## Phase 5: Add object-code branch coverage

Only after precise ranges and discontinuities exist, add branch outcomes.

1. Maintain the last normal execution record per vCPU.
2. Treat the next normal TB start as the observed successor.
3. Ignore/reset the pending edge when a discontinuity intervenes.
4. Classify the prior TB's terminal instruction through an internal decoder interface.
5. For a conditional direct branch, compare the successor with the direct target and architectural fall-through.
6. Count `taken`, `not_taken`, `other`, and `unresolved` separately.
7. Report calls, returns, unconditional jumps, indirect targets, and exceptions outside the two-outcome branch denominator.

Use libopcodes only when `insn_info_valid` is set, and add tested architecture adapters for its known gaps. Do not parse disassembly strings. Start with one relevant fixed-width ISA, then a variable-width ISA and a delay-slot ISA. AArch64 and MicroBlaze need adapters early if they are primary qemu-etrace targets.

Dynamic observations alone cannot provide a total percentage because unexecuted branches never appear. Add explicit denominator modes:

```text
manifest   trusted compiler/linker branch inventory
elf        decoded trusted executable ranges
observed   translated/seen sites only; diagnostic, not total coverage
```

Emit stable LCOV `BRDA` identifiers based on linked PC and outcome rather than discovery order.

## Compiler-assisted MC/DC: two different meanings

There are two substantially different compiler-assisted designs.

### Standard compiler instrumentation

GCC `-fcondition-coverage` and Clang `-fcoverage-mcdc` insert counter or bitmap updates into generated code. The compiler also emits source decision mappings. qemu-etrace can run at the same time and can transport or merge the resulting profile, but the MC/DC evidence comes from the compiler's instrumentation, not from QEMU branch edges.

For freestanding GCC guests, `-fprofile-info-section` and `__gcov_info_to_gcda()` can stream the profile without a guest filesystem. LLVM exposes buffer-oriented profile runtime APIs for the same kind of transport. This is the quickest supported route to source-level MC/DC, but it changes the generated instructions.

### Compiler metadata without inserted instructions

In principle, yes: a compiler can emit a sidecar mapping while leaving the executable instruction stream uninstrumented, and qemu-etrace can supply the runtime edges. A useful sidecar would need:

```text
build ID or exact code hash
source decision ID and source range
ordered atomic condition IDs and ranges
the decision's Boolean/BDD graph
for every observable condition, final machine PC and true/false successors
optimization, inline-instance, and clone identity
```

The analyzer could then reconstruct a ternary `T/F/X` vector for each decision evaluation and find MC/DC independence pairs.

This is not available by simply combining an ordinary uninstrumented C binary with today's GCC `.gcno`, Clang coverage map, or DWARF:

- GCC notes describe compiler CFG blocks and coverage counters, not a stable final machine-PC mapping for an uninstrumented executable.
- Clang's coverage map relates source regions to compiler profile counters. It is generated for the instrumentation workflow and does not provide a ready-to-use final branch-PC map.
- DWARF line tables locate instructions in source but do not encode decision boundaries, condition identity, Boolean structure, or evaluation vectors.
- optimization can replace a source condition with `cmov`, `csel`, predication, vector masks, or arithmetic, leaving no conditional branch edge for qemu-etrace to observe.

Historical GNATcoverage binary-trace workflows show that the concept can work when the compiler emits Source Coverage Obligations and preserves suitable control flow. For general C/C++, an equivalent non-instrumenting path requires a custom GCC or LLVM compiler pass that carries source condition IDs through optimization and final machine layout.

There are three ways to handle branchless lowering, none of them free:

1. constrain the compiler to preserve branch-observable control flow, which changes normal code generation even though it adds no probes;
2. teach QEMU to observe conditional selects/predicates and their input or result values, which is architecture-specific and considerably more expensive;
3. accept that those source conditions are unresolved and do not claim complete source MC/DC.

Therefore, treat non-instrumenting compiler metadata as an R&D phase after object branch coverage. Validate it against a second build using GCC/Clang's native MC/DC instrumentation. Do not put the plugin exit fix or object branch coverage on its critical path.

## MC/DC evaluation model

Any native qemu-etrace MC/DC path needs complete decision evaluations, not aggregate branch counts:

```c
struct decision_eval {
        uint64_t decision_id;
        uint64_t test_id;
        /* ordered T, F, or X values */
        condition_vector values;
        bool decision_result;
        bool complete;
};
```

For unique-cause MC/DC, a witnessing pair must change the condition of interest and the decision result while every other condition remains equal. For masking MC/DC, other changes are allowed only when the compiler-provided Boolean graph proves they are masked. Preserve the witness vectors and test IDs instead of only setting a covered bit.

Current LCOV supports `MCDC`, `MCF`, and `MCH` records, so compiler-imported and future native results can use the existing LCOV output family. Keep source MC/DC and object-code branch coverage as separate summaries.

## Proposed bisectable commit sequence

Each commit should include focused tests, a short imperative subject/body, and Edgar's `Signed-off-by`. No commit should depend on a later commit to build or pass.

1. `tests: Model instruction callbacks`
   Extend the plugin stubs to retain callbacks per translated instruction and execute selected prefixes in tests.
2. `plugin: Add instruction trace mode`
   Add `exec=insn`, exact instruction ranges, option validation, and raw/gzip tests.
3. `docs: Define dispatched coverage`
   Document TB, instruction, dispatch, retirement, and synchronous-exception semantics.
4. `etrace: Add discontinuity records`
   Add the packet format and consumer support before the producer emits it.
5. `build: Probe plugin discontinuities`
   Detect the callback declaration in the selected QEMU header rather than
   inferring it from the plugin API version.
6. `tests: Model plugin discontinuities`
   Add callback stubs and exception, interrupt, host-call, and callback-order
   fixtures.
7. `plugin: Record discontinuities`
   Emit the new packets when the feature probe enables the QEMU callback.
8. `tests: Model terminal latches`
   Add scoreboard and inline-store stubs and verify one terminal marker per TB.
9. `plugin: Track precise TB ranges`
   Add `exec=precise`, delayed per-vCPU emission, the optimized terminal-latch
   path, and the per-instruction fallback.
10. `etrace: Mark precise execution ranges`
    Add the info flag, validation, decoded provenance, and fixtures.
11. `tests: Exercise internal TB restarts`
    Cover MMIO replay, atomic re-execution, precise SMC, and watchpoint paths.
12. `tests: Exercise QEMU early exits`
    Add a real-QEMU fixture that traps in the middle and at the end of a TB.
13. `plugin: Default to precise ranges`
    Make the default change only after compatibility and performance results justify it.
14. `disas: Add control-flow decoding`
    Add the normalized one-instruction decoder and architecture golden tests.
15. `coverage: Track branch outcomes`
    Add per-vCPU normal edges, outcome counters, and discontinuity resets.
16. `coverage: Add branch inventories`
    Add manifest/ELF/observed denominator modes and unknown-site diagnostics.
17. `lcov: Emit branch coverage`
    Add stable `BRDA` records and differential tests against expected object edges.
18. `coverage: Import compiler MC/DC`
    Add one compiler-native format first, with explicit provenance and LCOV MC/DC output.

The first useful release point is after commit 2: users gain a correct but slow
exception-sensitive mode. The first efficient accuracy release is after commit
12. Object branch coverage begins only once that foundation is tested.

## Out of scope for the first milestones

- proving architectural retirement rather than dispatch;
- inferring source MC/DC from DWARF alone;
- claiming complete target coverage for indirect jumps without an expected target set;
- silently treating exception handler entry as a program branch;
- parsing human-readable disassembly as a semantic API;
- qualifying the tool for a safety standard.

## Sources

- [QEMU TCG plugin execution and exception semantics](https://www.qemu.org/docs/master/devel/tcg-plugins.html)
- [QEMU `cflow` plugin](https://github.com/qemu/qemu/blob/master/contrib/plugins/cflow.c)
- [GCC condition coverage](https://gcc.gnu.org/onlinedocs/gcc/Instrumentation-Options.html)
- [GCC freestanding coverage transport](https://gcc.gnu.org/onlinedocs/gcc/Freestanding-Environments.html)
- [Clang source coverage and MC/DC](https://clang.llvm.org/docs/SourceBasedCodeCoverage.html)
- [LLVM coverage mapping format](https://llvm.org/docs/CoverageMappingFormat.html)
- [LCOV MC/DC trace format](https://github.com/linux-test-project/lcov/blob/master/docs/man/geninfo.rst)
- [Research synthesis](../research/branch-mcdc.md)
