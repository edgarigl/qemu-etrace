# Hypervisor context filtering and context-aware traces

## Goal

Add an opt-in `context=hypervisor` producer mode that omits execution outside
the hypervisor while preserving enough boundary information for accurate
coverage and control-flow analysis.

At the same time, make unfiltered traces carry a small default set of
architectural mode and address-space registers. Post-processing tools can then
distinguish contexts such as firmware, hypervisor, guest kernel, guest
userspace, and individual address spaces without requiring the producer to
assign semantic names it cannot prove.

## Recommendation

Use two layers:

1. **Context sideband by default.** Record normalized execution mode plus a
   selected register tuple whenever it changes. Continue recording all
   execution ranges.
2. **Explicit producer filtering.** `context=hypervisor` applies an auditable
   classification policy and omits non-hypervisor `TYPE_EXEC` ranges while
   retaining context-boundary records.

The plugin should record architectural facts. Semantic labels such as
`firmware`, `hypervisor`, `guest-kernel`, or `process` belong primarily in the
analyzer and must carry classification provenance.

## Why privilege level is insufficient

Privilege does not identify a hypervisor by itself:

- Xen and a guest kernel can both execute at x86 CPL0.
- Firmware, a hypervisor, and an operating-system kernel can all execute in
  privileged modes.
- Nested guests can use the same architectural privilege level as their host.
- CPL3 or EL0 identifies userspace but not a process name.
- CR3, TTBR, SATP, ASID, and VMID values distinguish address spaces but need
  OS or firmware metadata to acquire semantic names.

A robust classifier combines executable identity, privilege, address-space
identity, and virtualization state. Any unavailable component must be marked
invalid rather than replaced with a guessed value.

## Current QEMU plugin constraints

The public plugin API provides:

- `qemu_plugin_get_registers()` during vCPU initialization;
- `qemu_plugin_read_register()` in callbacks with register-read access;
- `QEMU_PLUGIN_CB_R_REGS` to request that access;
- TB-entry and instruction callbacks;
- discontinuity callbacks for interrupts, exceptions, and host calls;
- per-vCPU scoreboards and inline operations.

The public API does not provide a portable normalized tuple containing:

```text
privilege level
firmware/security state
virtualization root versus guest state
ASID or address-space root
VMID or nested virtual-machine identity
```

Register enumeration is based on QEMU's target/GDB register model. Some
control registers or internal virtualization flags may be unavailable. In
particular, architectural x86 registers alone may not reliably distinguish SVM
root execution from a nested guest. A future QEMU context API would make this
substantially cleaner.

## Context record model

Emit a context record only when the selected state tuple changes. The fixed
portion should expose target-neutral fields useful to generic consumers:

```c
struct etrace_context {
        uint64_t sequence;          /* monotonic within unit_id */
        uint64_t context_id;        /* ID for this complete state tuple */
        uint64_t pc;                /* first TB observed in this context */
        uint64_t address_space_id;  /* normalized CR3/TTBR/SATP value */
        uint64_t virtual_machine_id;
        uint32_t flags;
        uint16_t architecture;
        uint8_t privilege;
        uint8_t register_count;
        /* register-value TLVs follow */
};
```

Candidate flags could include:

```text
PAGING
LONG_MODE
SECURE
VIRTUALIZED
VIRTUALIZATION_ROOT
FIRMWARE_CANDIDATE
HYPERVISOR_CANDIDATE
KERNEL_CANDIDATE
USER_CANDIDATE
INCOMPLETE
```

Candidate classifications need confidence and provenance. Register values and
normalized architectural mode are evidence; a label derived from them is an
interpretation.

### Register schema

Add a schema record that maps compact register IDs to the runtime register
descriptors selected by the plugin:

```text
register ID
QEMU register name
architectural role
width
target byte order
```

Context records can then append compact TLVs:

```c
struct etrace_context_register {
        uint16_t id;
        uint16_t size;
        uint32_t flags;
        uint8_t value[];
};
```

This avoids fixing every architecture-specific register in the base packet.
The normalized fields remain available even when a consumer does not
understand a target-specific register name.

## Default register sets

A default `context-registers=basic` mode should contain only mode,
translation, and virtualization state:

| Architecture | Suggested state |
|---|---|
| x86 | CS, RFLAGS, CR0, CR3, CR4, EFER |
| AArch64 | PSTATE/CPSR, TTBR0, TTBR1, HCR_EL2, VTTBR_EL2, SCR_EL3 |
| RISC-V | privilege mode, `mstatus`, `sstatus`, `satp`, `hstatus`, `hgatp` |

The actual tuple is limited to registers exposed by the selected QEMU build.
Each normalized field needs a validity bit.

Suggested options:

```text
context-registers=none
context-registers=basic
context-registers=all
context-registers=cs,cr0,cr3,cr4,efer
```

General-purpose registers should not be part of the default tuple. They add
substantial overhead, increase trace size, and may expose guest data.

## Delayed execution-range ordering

The current plugin delays a TB's execution range until the next TB entry,
discontinuity, vCPU exit, or plugin exit. Context must therefore be captured
with the pending TB rather than attached to whichever context is current when
the range is finally written.

Extend the per-vCPU state conceptually as follows:

```c
struct vcpu_exec_state {
        struct tb_data *pending;
        uint64_t progress;
        uint64_t pending_context_id;
        bool pending_included;
        bool seen;
};
```

At entry to TB B:

```text
sample context B
        |
resolve pending TB A using saved context A
        |
emit CONTEXT(A) if the output stream needs it
        |
emit EXEC(A), or record a filtered boundary
        |
install TB B with context B and its filter result
```

This ordering is required around interrupts, exceptions, `VMRUN`, and
`VMEXIT`. Registers sampled at TB B describe B and must not be assigned to the
range belonging to A.

At a discontinuity, flush the pending range with its saved context before
recording the discontinuity. The handler's context is sampled at its first TB.

At vCPU or plugin exit, flush each pending range with its saved context before
the final producer-status record.

## Sampling strategy

### Correctness reference

Use the existing TB-entry host callback with `QEMU_PLUGIN_CB_R_REGS` and read
the selected basic registers on every TB entry. Compare the resulting tuple
with the vCPU's previous tuple and emit a context record only on change.

This adds no new callback, but requesting register access and reading several
registers can force CPU-state synchronization. Measure its cost separately
from trace I/O.

Reuse per-vCPU `GByteArray` buffers and register handles discovered at vCPU
initialization. Avoid allocation in the TB hot path.

### Later optimization

Architecture adapters can mark context dirty for instructions and events that
can change it:

- control-register writes;
- page-table or address-space switches;
- syscall, exception, interrupt, and return paths;
- `VMRUN`, `VMLAUNCH`, VM exits, and equivalent transitions;
- changes to secure, exception-level, or virtualization state.

The next TB entry reads registers only when the state is dirty. This requires
careful architecture testing because some changes occur without an ordinary
instruction callback.

A dedicated QEMU context-change callback would be preferable to maintaining a
complete architecture-specific dirty-instruction list.

## Initial `context=hypervisor` classifier

The first Xen implementation should use an explicit executable-range
manifest. The definition is simple and auditable:

```text
hypervisor := current PC belongs to a declared Xen executable range
```

Example plugin options:

```text
context=hypervisor
context-range=0xffff82d040000000:0x6b1198
context-range=0x1d600000:0x6b1198
context-unknown=error
context-registers=basic
```

The linked range covers normal Xen execution and the early range covers its
temporary physical mapping. The Xen test helper can generate these options
from `xen-syms.debug` and the existing ETrace address-map metadata.

Do not hard-code Xen's canonical address shape in the plugin. Firmware,
hypervisors, relocatable kernels, and early boot mappings all need explicit
image/range provenance.

Longer-term classifiers can combine:

```text
executable identity
+ privilege level
+ address-space identity
+ virtualization root/guest state
```

If a required fact is unavailable, `context-unknown=error` prevents silent
loss of coverage evidence. Optional alternatives may include `keep` and
`drop`, but they must remain explicit in trace metadata.

## Filtering semantics

When `context=hypervisor` is active:

- included hypervisor `TYPE_EXEC` ranges are emitted normally;
- guest, firmware, kernel, and userspace ranges are omitted;
- context sampling continues while execution is omitted;
- leaving or entering the included set emits a filtered-context boundary;
- branch and transition consumers reset pending normal-edge state at that
  boundary;
- producer status reports the number of filtered TBs or ranges and any
  unknown-context or context-read failures.

Without a boundary record, a consumer could incorrectly connect the last
hypervisor TB before guest entry to the first hypervisor TB after guest exit.

A boundary record could carry:

```c
struct etrace_context_gap {
        uint64_t sequence;
        uint64_t from_context_id;
        uint64_t to_context_id;
        uint32_t reason;
        uint32_t flags;
};
```

Alternatively, the first context record after a gap can carry a
`FILTERED_SINCE_PREVIOUS` flag. Either representation must force control-flow
analysis to discard pending normal edges.

Discontinuities crossing an included/excluded boundary remain useful. They
should identify whether the source or destination context was filtered without
requiring guest execution ranges to be retained.

## Static range optimization

An explicit PC-range classifier can decide inclusion at translation time.
Definitely excluded TBs do not need per-instruction progress stores because
their ranges will never be emitted. They still need enough TB-entry state to:

- flush a preceding included TB;
- mark the beginning of a filtered gap;
- detect re-entry into an included range.

If filtering depends on runtime register state, the same translated TB can be
included in one context and excluded in another. In that case it must retain
the normal instrumentation, and inclusion is decided at execution time.

## Default all-context post-processing

With context filtering disabled, post-processing can infer progressively more
specific identities:

- firmware from image ranges and reset, secure, or exception-level state;
- hypervisor from executable identity and virtualization-root state;
- guest kernels from guest virtualization state plus privileged mode;
- userspace from CPL3 or EL0 plus address-space identity;
- distinct address spaces from CR3, TTBR, SATP, ASID, or VMID changes.

Mapping an address-space ID to a process name needs OS-aware sideband data,
debug symbols, page-table information, task-switch probes, or a guest agent.
The trace should preserve the raw address-space identity even when no process
name is available.

## Trace provenance and validity

Context-aware traces should record:

```text
selected register schema
register availability and read failures
classifier kind and version
included context classes or ranges
range-manifest or executable hash
unknown-context policy
filtered TB/range counts
context transition count
```

Unknown context in an `error` policy and any required register-read failure
must make final producer status invalid.

### Format compatibility

Default traces remain execution-complete. Older consumers can safely ignore
unknown context sideband packets while processing all `TYPE_EXEC` ranges.

Filtered traces intentionally omit execution and must not be interpreted as
complete by an older converter. A new information flag is insufficient because
legacy consumers ignore unknown flags. Filtered traces should therefore use a
format-major version that legacy converters reject, or another mandatory
versioned envelope with equivalent fail-closed behavior.

LCOV and other outputs generated from filtered traces must record the filter
policy as provenance. A hypervisor ELF denominator is appropriate only when
the filter manifest covers every runtime mapping of that hypervisor.

## Performance considerations

Measure at least:

- slowdown relative to current full tracing;
- cost of `QEMU_PLUGIN_CB_R_REGS` with no register reads;
- cost per selected register read;
- TB callback count and state synchronization;
- number and size of emitted context records;
- reduction in raw and gzip trace size under hypervisor filtering;
- MTTCG lock contention when contexts change concurrently;
- translation-cache growth with and without static range exclusion.

The correctness-reference implementation can read the basic tuple at every TB
entry. Performance results should guide dirty-state optimization, not weaken
context classification silently.

## Security and privacy

Mode and address-space registers are less sensitive than general-purpose
registers but can still expose address-space layout and workload structure.
Trace metadata should state which registers are present. Capturing all
registers requires an explicit option.

Filtering must not leak excluded guest register values through boundary
records unless explicitly requested. A boundary can refer to an opaque context
ID and normalized class without serializing its complete raw tuple.

## Desirable QEMU API

A target-neutral QEMU plugin API could expose:

```c
struct qemu_plugin_vcpu_context {
        uint64_t address_space_id;
        uint64_t virtual_machine_id;
        uint32_t flags;
        uint8_t privilege;
        uint8_t security_state;
        uint8_t virtualization_level;
};
```

Useful flags include paging, userspace, virtualization root/guest, secure
state, and field validity. A callback on changes would avoid polling registers
at every TB entry and expose internal virtualization state that is absent from
the public register list.

The raw-register path remains valuable for architecture-specific analysis and
for older QEMU versions.

## Proposed implementation sequence

1. Define context schema, context-change, and filtered-boundary packets.
2. Add consumer validation, readable output, and Python fixture support.
3. Model per-vCPU register discovery and reads in the plugin test API.
4. Implement x86 `context-registers=basic` with validity masks.
5. Attach context IDs to delayed pending ranges and emit only context changes.
6. Add explicit range-based `context=hypervisor` filtering for Xen.
7. Reset discontinuity and normal-edge state across filtered boundaries.
8. Add producer-status counters for filtering and context-read failures.
9. Benchmark raw/gzip size, callback overhead, and MTTCG behavior.
10. Add AArch64 and RISC-V normalized context adapters.
11. Prototype dirty-state sampling and compare it with per-TB polling.
12. Propose a normalized QEMU execution-context API.

## Acceptance criteria

- Default tracing retains every execution range and emits context sideband
  only when the selected state changes.
- A context record always describes the delayed range to which it is attached,
  including around interrupts, exceptions, VMRUN, and VM exits.
- Hypervisor range filtering includes linked and early runtime mappings.
- No guest `TYPE_EXEC` range appears in a hypervisor-filtered trace.
- Every excluded interval creates a boundary that resets normal-edge state.
- Unknown required context makes the producer status invalid.
- Missing optional registers are represented with validity flags.
- Interleaved MTTCG vCPUs maintain independent context and sequence state.
- vCPU and plugin shutdown flush pending ranges with their captured context.
- Legacy consumers cannot silently interpret a filtered trace as complete.
- Default context capture and hypervisor filtering have measured performance
  and trace-size results.

## Open questions

- Which mode and address-space registers are consistently exposed by QEMU for
  each supported architecture and release?
- Can x86 SVM/VMX root-versus-guest state be derived from public registers, or
  is a new QEMU API mandatory?
- Should context IDs be global across vCPUs or local to `unit_id`?
- Should raw context tuples be dictionary-compressed and referenced by ID?
- Does a filtered boundary need both source and destination context IDs, or is
  an opaque gap sufficient?
- Should early physical hypervisor ranges be supplied directly to the plugin
  or derived from a signed trace manifest?
- Which context fields are acceptable in default traces from a privacy and
  certification perspective?
