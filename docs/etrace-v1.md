# ETrace version 1

ETrace version 1 adds a translation-block dictionary and context-aware
execution records. It is selected explicitly with the QEMU plugin option
`format=v1`. Version 0 output remains the default.

The version 1 records use the existing packed ETrace packet envelope and
native byte order. They are an incremental semantic format, not yet the
portable little-endian container discussed in `research/trace-formats.md`.

## Processing model

The producer separates immutable translation definitions from dynamic
execution observations:

```text
TYPE_TB_DEF       TB ID to instruction boundaries and physical mappings
TYPE_CONTEXT      Context ID to normalized state and selected registers
TYPE_TB_EXEC      TB ID, dispatched instruction count, and context ID
TYPE_CONTEXT_GAP  Omitted execution interval
```

`qemu-etrace` keeps the definitions in a streaming dictionary. A
`TYPE_TB_EXEC` is expanded into the same exact half-open execution range used
by version 0, QEMU simpletrace, and hexadecimal traces. Existing line and
function coverage therefore share one processing path and do not depend on
the producer's physical encoding.

The dispatched instruction count preserves partial-TB execution. A TB ID must
be defined before use, IDs cannot be reused, instruction layouts must be
contiguous, and optional mapping segments must cover the complete TB.

## Plugin options

Create a compact version 1 trace with:

```sh
-plugin libqemu-etrace.so,out=trace.etrace,format=v1
```

Version 1 requires QEMU plugin API 2 or newer. Version 0 continues to work with
API version 1.

Capture a target-specific basic context tuple with:

```sh
-plugin libqemu-etrace.so,out=trace.etrace,format=v1,context-registers=basic
```

The initial basic sets are:

| Target | Registers requested from QEMU |
|---|---|
| x86 and x86-64 | `cs`, `eflags`, `cr0`, `cr3`, `cr4`, `efer` |
| AArch64 | `cpsr`, `ttbr0_el1`, `ttbr1_el1`, `tcr_el1`, `sctlr_el1`, `hcr_el2`, `vttbr_el2`, `vtcr_el2`, `scr_el3` |
| RISC-V | `priv`, `mstatus`, `sstatus`, `satp`, `hstatus`, `hgatp` |

The registers actually available depend on QEMU's target/GDB register model.
A missing or unreadable requested register marks the context incomplete and
increments `context_errors`; the converter then rejects the trace for coverage
use. Raw register values use target byte order.

Use `context-registers=all`, `context-registers=none`, or repeat an explicit
selection:

```sh
...,context-register=cs,context-register=cr3
```

Capturing all registers is explicit because it can be expensive and can expose
guest data. Register capture requires plugin API 2 or newer.

## Hypervisor filtering

The initial hypervisor classifier uses explicit half-open executable ranges:

```sh
-plugin libqemu-etrace.so,out=xen.etrace,format=v1,context=hypervisor,\
context-range=0xffff82d040000000:0x6b1198,\
context-range=0x1d600000:0x6b1198
```

Every TB must be wholly inside or outside a declared range. A TB crossing a
range boundary increments `context_errors`, making the completed trace invalid.
Definitions and executions for excluded TBs are omitted. Consecutive excluded
executions are represented by one `TYPE_CONTEXT_GAP`, which prevents a
consumer from constructing a false edge between the included executions on
either side.

Range filtering requires version 1 but does not require register access. It
therefore works with plugin API 2. Register state can be enabled independently
to make the captured context useful for later OS-aware analysis.

## Observed execution mappings

Add `exec-mapping=on` to place virtual-to-physical mapping segments in each TB
definition. This requires plugin API 5 or newer and system emulation:

```sh
-plugin libqemu-etrace.so,out=trace.etrace,format=v1,exec-mapping=on
```

The plugin samples `qemu_plugin_translate_vaddr()` while the TB is translated.
It coalesces physically contiguous instruction bytes and preserves
discontinuities as separate segments. A failed translation increments
`mapping_errors`, making the completed trace invalid.

These are observations for translated instruction bytes, not a complete MMU
map. The public plugin API has no mapping-change or TLB-fill callback, and the
translation helper does not expose page size, permissions, intermediate
translation stages, or architectural TLB residency. Unexecuted data mappings
cannot be reconstructed from these records.

## Compatibility

Version 0 readers reject version 1 at the information record. This is required
for filtered traces: an old reader must not silently treat an intentionally
partial trace as complete coverage.

The version 1 final status extends the version 0 prefix with filtered-execution,
context-error, and mapping-error counters. Filtering itself is not an error;
context or mapping failures are.
