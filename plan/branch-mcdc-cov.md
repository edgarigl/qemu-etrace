# Branch and MC/DC coverage plan

## Current status

The execution-accuracy foundation is implemented:

- API version 1 records exact per-instruction execution ranges.
- API version 2 and newer use per-vCPU scoreboards and delayed range
  emission.
- System emulation with discontinuity support uses one terminal-instruction
  latch per TB.
- Older QEMU and user-mode emulation use a per-instruction inline progress
  marker.
- Exceptions, interrupts, and host calls have explicit discontinuity records.
- The build probes the selected QEMU header for discontinuity support instead
  of inferring support from the plugin API version.
- Execution coverage and DWARF attribution operate at byte granularity and
  already support variable-length instructions.
- A normalized one-instruction decoder and AArch64 control-flow adapter cover
  conditional branches, jumps, calls, returns, traps, direct targets, and
  fall-through addresses.

The plugin bookkeeping is covered with API versions 1, 5, and 7, including
QEMU 10.1-style version 5 without discontinuities and QEMU 10.2-style version
5 with discontinuities. A real-QEMU regression that deliberately faults in
the middle of a multi-instruction TB remains useful integration coverage.

## Updated recommendation

Make the QEMU plugin responsible for recording runtime control-flow facts and
the analyzer responsible for assigning object-code semantics:

1. add an explicit normal-transition packet containing the executed TB,
   exact last dispatched instruction PC, and observed successor PC;
2. emit normal transitions from the plugin's existing delayed per-vCPU state;
3. classify transition sources with the normalized decoder and derive branch
   outcomes;
4. add trusted static branch inventories and LCOV `BRDA` output;
5. extend decoding from AArch64 to a variable-width ISA and a delay-slot ISA;
6. add optional predicate/register capture only for cases where an observed
   control-flow edge is insufficient;
7. import compiler-instrumented MC/DC results;
8. investigate non-instrumenting compiler metadata as a separate compiler
   project.

This avoids reconstructing a terminal instruction boundary from an execution
range. It also keeps architecture-specific interpretation out of the hot
plugin path while preserving the exact control flow observed by QEMU.

## Coverage terminology

### Dispatched-instruction coverage

QEMU plugin execution instrumentation runs before an instruction completes.
An instruction callback proves dispatch, not architectural retirement. A
faulting instruction may not retire and can be absent from general execution
callbacks on some exception paths. Ordinary execution ranges therefore
describe dispatched instructions; discontinuity records describe exceptional
sources separately.

### Object-code branch coverage

An object-code conditional branch has two expected successors:

- `taken`: the observed successor equals the decoded direct target;
- `not_taken`: the observed successor equals architectural fall-through.

Retain two additional outcomes:

- `other`: a normal successor is observed but matches neither expected edge;
- `unresolved`: the instruction, code identity, or successor is unavailable or
  cannot be classified safely.

Calls, returns, unconditional jumps, indirect targets, traps, and
discontinuities remain visible but stay outside the two-outcome conditional
branch denominator.

### Source MC/DC

Source MC/DC requires complete evaluations of source-level decisions and
independence pairs between their atomic conditions. Object branch outcomes do
not supply source decision identity or Boolean structure. Keep source MC/DC
and object-code branch coverage as separate metrics and summaries.

## Existing execution-range contract

Every unmarked `TYPE_EXEC` range is accurate. The format does not use a
positive precision flag because accuracy is the default contract for legacy
and current traces. Any future optimistic producer must opt out with an
explicit inaccuracy flag.

The optimized plugin retains every translated instruction boundary in its
immutable `tb_data`. The serialized `TYPE_EXEC` record contains only the
half-open byte range. This is sufficient for byte and source-line coverage,
including variable-length x86 instructions, but it does not reveal where the
last instruction in a multi-instruction range begins.

That distinction drives the next format addition: branch analysis needs an
exact source instruction PC, while ordinary coverage does not.

## Plugin-assisted normal transitions

Add a versioned packet for normal execution transitions. The exact layout may
be adjusted during implementation, but it must carry at least:

```c
struct etrace_transition {
        uint64_t sequence;      /* monotonic within unit_id */
        uint64_t tb_start;      /* start of the completed TB execution */
        uint64_t last_pc;       /* exact last dispatched instruction PC */
        uint64_t next_pc;       /* next normal instruction to execute */
        uint32_t flags;
        uint32_t reserved;
};
```

The ETrace header supplies `unit_id`. `last_pc` preserves the terminal
instruction boundary for variable-width ISAs. `tb_start` lets a delay-slot
adapter inspect the complete executed suffix and find a controlling branch
that precedes the final dispatched instruction. `sequence` prevents global
packet interleaving under MTTCG from being mistaken for per-vCPU order.

A normal transition is a runtime fact, not yet a branch classification. It can
represent a conditional branch, an unconditional transfer, a call, a return,
or an ordinary QEMU TB split. The analyzer decides which case applies.
The baseline producer must not attach an architecture-specific taken or
not-taken label; a delay-slot branch might not even reside at `last_pc`.

### Producer algorithm

At translation time:

1. retain the TB start, nominal end, final instruction PC, instruction
   boundaries, and final instruction bytes in immutable `tb_data`;
2. retain one terminal latch per TB when discontinuities are available;
3. retain per-instruction progress for compatibility configurations.

At the next TB entry:

1. resolve and emit the pending accurate execution range;
2. determine whether the pending TB reached its translated terminal
   instruction;
3. if it did, emit a normal transition from the pending TB to the new TB;
4. install the new TB as pending.

No additional host callback is needed on the normal API-version-2-or-newer
path because the existing TB-entry callback already performs delayed range
resolution.

At a discontinuity:

- an exception or host call ends the ordinary prefix and does not produce a
  normal transition to the handler;
- an interrupt occurs between TBs, so a completed pending TB can first resolve
  a normal transition to the callback's would-have-executed `from_pc`;
- the discontinuity packet then records the transfer to `to_pc` and clears
  pending program-edge state.

At vCPU exit, flush the pending execution range exactly once. A completed
terminal branch with no observable successor remains unresolved; do not invent
an outcome.

Internal QEMU restarts such as MMIO retranslation, atomic re-execution,
precise self-modifying-code handling, and watchpoint handling must not become
program edges. Preserve a diagnostic or internal-transition flag when useful,
but exclude such transitions from branch coverage.

One transition per completed TB adds trace traffic. Measure raw and gzip size,
callback count, write-lock contention, and SMP throughput. Preserve event
sequence for future decision reconstruction; aggregation is suitable only for
an explicitly branch-summary-only producer mode.

### Older API compatibility

API version 1 already emits one exact range per dispatched instruction. Its
consumer can derive normal successors from adjacent per-vCPU instruction
records. The plugin may emit explicit transition packets for consistency, but
must not weaken the existing correctness reference.

The API-version-2 fallback can map its last-dispatched-end scoreboard value
back to the retained instruction boundaries. A transition is normal only when
the terminal instruction was dispatched.

## Translated instruction identity

For the first AArch64 milestone, the analyzer may read instruction bytes from
a trusted ELF image after applying the configured runtime address map. Missing
or mismatched bytes produce an unresolved observation rather than a guessed
branch.

Runtime-generated and self-modifying code require stronger identity. Add a
translated-code definition before claiming support for those cases. A useful
definition contains:

```text
translation ID
virtual and optional physical address
ordered instruction boundaries
translated guest bytes
code hash
```

Normal-transition records can then reference the translation ID. Repeated
translations at one virtual address remain distinct when their bytes differ.
The existing `TYPE_TB` packet can inform the design, but it lacks a stable
translation ID and explicit instruction boundaries.

## Phase 1: Add normal-transition records

Add the format definition, validation, human-readable output, and Python
fixture support before changing the producer.

Acceptance criteria:

- malformed and short packets are rejected consistently;
- unknown flag bits follow an explicit forward-compatibility policy;
- 32-bit guests retain full internal addresses without truncating the packet;
- per-vCPU sequence numbers are monotonic;
- human and Python decoders expose all fields;
- legacy traces remain readable.

## Phase 2: Emit plugin transitions

Extend the plugin's pending-TB state to emit normal transitions as part of
range resolution.

Acceptance criteria:

- taken and fall-through branches report the exact terminal instruction PC
  and observed successor;
- ordinary QEMU TB splits are reported as transitions and later ignored by
  branch classification;
- variable-width terminal instructions use QEMU's recorded start address;
- exceptions and host calls never produce normal handler edges;
- an interrupt can resolve the pre-interrupt normal successor from
  discontinuity `from_pc`, while handler entry remains a discontinuity;
- internal restarts are not reported as program branches;
- vCPU state and sequence numbers never cross CPUs under MTTCG;
- the final unresolved transition is not fabricated at vCPU shutdown;
- API versions 1, 5 without discontinuities, 5 with discontinuities, and 7
  build and pass.

## Phase 3: Derive dynamic branch outcomes

Consume normal transitions and classify the controlling instruction through
the normalized decoder.

For AArch64, a completed branch normally resides at `last_pc`. Compare
`next_pc` with its decoded target and fall-through. Cache immutable decoded
sites by build identity, linked PC, and code identity rather than decoding on
every execution.

Maintain counters keyed by linked branch PC:

```c
struct branch_observation {
        uint64_t taken;
        uint64_t not_taken;
        uint64_t other;
        uint64_t unresolved;
};
```

Also retain separate summaries for direct jumps, indirect targets, calls,
returns, traps, and discontinuities. These are useful control-flow evidence
but are not conditional branch outcomes.

Acceptance criteria:

- both outcomes of `b.cond`, `cbz`/`cbnz`, and `tbz`/`tbnz` are counted;
- repeated execution accumulates at a stable linked PC;
- direct branches to address zero remain valid direct targets;
- `other` and `unresolved` never count as covered expected outcomes;
- interleaved vCPUs resolve independently;
- address maps are applied before ELF lookup and site aggregation;
- missing, mismatched, or unsupported code is diagnosed and remains
  unresolved;
- calls, returns, jumps, and traps stay outside the conditional denominator.

## Phase 4: Add branch inventories and LCOV output

Dynamic observations cannot provide a complete denominator because an
unexecuted branch never appears. Support explicit inventory modes:

```text
manifest   trusted compiler/linker branch inventory
elf        decoded trusted executable ranges
observed   translated or seen sites only; diagnostic, not total coverage
```

The ELF scanner must use the same normalized decoder and code-identity rules
as dynamic classification. Emit stable LCOV `BRDA` identifiers based on linked
PC and expected outcome rather than discovery order.

Acceptance criteria:

- unexecuted inventory branches appear with zero covered outcomes;
- taken and not-taken IDs remain stable across trace orderings;
- unknown executable bytes and unsupported instructions produce diagnostics;
- observed-only mode is clearly labelled and does not claim total coverage;
- source locations use the existing DWARF and address-map machinery;
- LCOV totals agree with hand-authored AArch64 branch fixtures.

## Phase 5: Extend architecture coverage

Add one variable-width ISA and one delay-slot ISA after the AArch64 path is
complete.

### x86/x86-64

The execution-range coverage path already handles variable-length
instructions. Branch decoding must begin at the plugin-provided `last_pc`, not
at `range.end - constant_width`. Cover conditional jumps, direct and indirect
jumps, calls, returns, and loop-family branches with golden encodings.

### MicroBlaze

Use `tb_start`, ordered instruction boundaries, and `last_pc` to associate a
successor with a branch before its delay slot. Test delayed conditional and
unconditional branches, returns, traps, and exceptions in the delay slot. Do
not treat `branch_delay_insns` as a complete description of annul or
branch-likely semantics on architectures that provide them.

Continue to use libopcodes metadata only when `insn_info_valid` is set. Add
small architecture adapters for missing return, directness, trap, target, and
delay semantics. Never parse rendered disassembly text.

## Optional predicate and register capture

Baseline branch coverage does not require register reads. For a decoded
conditional branch, the observed successor establishes whether its encoded
predicate evaluated true or false.

QEMU exposes register enumeration and reads in callbacks that request register
access. Use this only as an opt-in extension for:

- validating decoded branch predicates against observed successors;
- conditionally executed or conditional-select instructions that do not
  create a branch edge;
- architecture investigations and diagnostics;
- compiler-provided condition mappings that explicitly identify required
  machine values.

Register capture requirements:

- register handles are discovered per vCPU with
  `qemu_plugin_get_registers()`;
- values are read in a pre-execution instruction callback with register-read
  access using `QEMU_PLUGIN_CB_R_REGS` and `qemu_plugin_read_register()`;
- target byte order and register width are recorded explicitly;
- only selected sites receive callbacks;
- raw values are optional because they increase trace volume and may expose
  guest data;
- a normalized predicate result is preferred when sufficient;
- architecture-specific tests verify callback timing and condition
  evaluation.

For AArch64 this can cover NZCV for `b.cond` and the selected register for
`cbz`/`cbnz` and `tbz`/`tbnz`. Equivalent support for x86 requires flags and,
for loop-family instructions, counter-register state. These values explain a
machine predicate; they do not by themselves establish source MC/DC.

Before capturing registers, extend the normalized decoder with a predicate
descriptor containing the condition family, encoded condition, register
number and width, and tested bit where applicable. Keep that static descriptor
separate from optional runtime values.

## Compiler-assisted MC/DC

### Standard compiler instrumentation

GCC `-fcondition-coverage` and Clang `-fcoverage-mcdc` insert counter or bitmap
updates and emit source decision mappings. qemu-etrace can transport or merge
the resulting profile. This is the shortest supported route to source-level
MC/DC, while explicitly acknowledging that instrumentation changes generated
instructions.

For freestanding GCC guests, `-fprofile-info-section` and
`__gcov_info_to_gcda()` can stream profile data without a guest filesystem.
LLVM provides buffer-oriented profile runtime APIs for equivalent transport.

### Compiler metadata without inserted instructions

A non-instrumenting design requires compiler-emitted metadata containing at
least:

```text
build ID or exact code hash
source decision ID and source range
ordered atomic condition IDs and ranges
decision Boolean or BDD graph
machine PC and true/false successors for each observable condition
optimization, inline-instance, and clone identity
```

The analyzer can combine that metadata with transition and optional predicate
records to reconstruct ternary `T/F/X` decision vectors. This information is
not available from ordinary DWARF, uninstrumented GCC `.gcno`, or Clang
coverage maps.

Optimization can replace source conditions with conditional selects,
predication, vector masks, or arithmetic. Handle those cases by constraining
code generation, explicitly observing the relevant machine values, or marking
the source condition unresolved. Do not infer complete source MC/DC from
branch outcomes alone.

For unique-cause MC/DC, a witnessing pair must change the condition of
interest and the decision result while every other condition remains equal.
For masking MC/DC, other changes are allowed only when the compiler-provided
Boolean graph proves they are masked. Preserve witness vectors and test IDs.

Current LCOV supports `MCDC`, `MCF`, and `MCH` records. Keep compiler-imported
and future native results separate from object-code `BRDA` coverage.

## Updated bisectable commit sequence

Each commit includes focused tests, a short imperative subject and body, and
Edgar's `Signed-off-by`. Every commit builds and passes independently.

Completed foundation:

1. exact instruction callbacks and dispatched-coverage semantics;
2. discontinuity format, validation, feature probing, and plugin emission;
3. terminal-latch and inline-progress execution-range tracking;
4. byte-accurate variable-length execution coverage;
5. normalized control-flow decoding and AArch64 golden tests.

Remaining sequence:

1. `etrace: Add normal transition records`
   Add the packet, validation, readable output, and Python fixtures.
2. `tests: Model plugin transitions`
   Extend plugin stubs for normal successors, interrupts, exceptions,
   internal restarts, vCPU exit, and interleaved CPUs.
3. `plugin: Record normal transitions`
   Emit per-vCPU transition facts from the existing delayed execution state.
4. `coverage: Resolve branch outcomes`
   Add the pure outcome resolver and AArch64 unit tests.
5. `coverage: Track observed branches`
   Integrate transition decoding, address mapping, caching, counters, and
   diagnostics.
6. `coverage: Add branch inventories`
   Add manifest, ELF, and observed denominator modes.
7. `lcov: Emit branch coverage`
   Add stable `BRDA` records and end-to-end AArch64 fixtures.
8. `disas: Decode x86 control flow`
   Add variable-width branch classification and golden tests.
9. `disas: Decode MicroBlaze control flow`
   Add delay-slot-aware classification and golden tests.
10. `trace: Identify translated code`
    Add translation IDs, instruction boundaries, and code bytes for dynamic
    or self-modifying code.
11. `disas: Describe AArch64 predicates`
    Add normalized condition and operand descriptors for conditional branches.
12. `plugin: Capture selected predicates`
    Add an opt-in register-assisted mode after its packet semantics and
    performance budget are defined.
13. `coverage: Import compiler MC/DC`
    Add one compiler-native format with provenance and LCOV MC/DC output.

The first new release point is after commit 7: AArch64 object branch coverage
with a trusted inventory and explicit normal transitions. Variable-width and
delay-slot architectures follow without changing the transition format.

## Validation matrix

- API version 1, version 5 without discontinuities, version 5 with
  discontinuities, and version 7 plugin builds;
- raw and gzip traces decode identically;
- AArch64 taken, not-taken, unexpected, and unresolved successors;
- direct target address zero and signed backward targets;
- interrupt between a branch and its next normal instruction;
- middle- and terminal-instruction exceptions;
- repeated TBs and interleaved MTTCG vCPUs;
- final pending TB at vCPU shutdown;
- x86 variable-width terminal instructions;
- MicroBlaze branches and exceptions involving delay slots;
- translation-cache flush and self-modifying code identity;
- differential branch results against hand-authored ISA fixtures and QEMU's
  `cflow` plugin;
- compiler MC/DC imports against `gcov --conditions` or
  `llvm-cov --show-mcdc`.

## Out of scope for the first branch milestone

- proving architectural retirement rather than dispatch;
- inferring source MC/DC from DWARF alone;
- reading raw registers for ordinary branch outcome accounting;
- claiming complete indirect-target coverage without an expected target set;
- treating exception-handler entry as a normal program branch;
- parsing human-readable disassembly as a semantic API;
- complete support for runtime-generated or self-modifying code before code
  identity records exist;
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
