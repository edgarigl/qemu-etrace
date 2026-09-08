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

### Online UNIX socket

The upstream plugin accepts a connect-only UNIX destination. qemu-etrace owns
the listener, eliminating the connect/listen race in the older symmetric
socket convention:

```sh
socket=/tmp/xen-etrace.sock
rm -f "$socket"
qemu-etrace --trace "unix:$socket" --server 0 \
    --elf xen-syms.debug --auto-map --preserve-order \
    --coverage-format lcov --coverage-output xen.info \
    --trace-output none &
analyzer_pid=$!
while test ! -S "$socket"; do sleep 0.01; done

qemu-system-x86_64 ... \
    -plugin "/path/libqemu-etrace.so,out=unix:$socket,format=v1,\
context=hypervisor,context-range=$xen_linked_start:$xen_size,\
context-unmatched=keep,context-registers=basic,exec-mapping=on"
qemu_status=$?
wait "$analyzer_pid"
analyzer_status=$?
test "$qemu_status" -eq 0 -a "$analyzer_status" -eq 0
```

Raw and `compress=gzip` streams are supported. A missing listener fails plugin
installation. Peer disconnects become output failures; qemu-etrace rejects a
truncated stream without its required final producer status.

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

When the hypervisor's early physical load address is unknown, add
`context-unmatched=keep`. TBs inside a declared range retain the hypervisor
flag; other TBs are emitted with an incomplete context rather than discarded:

```sh
-plugin libqemu-etrace.so,out=xen.etrace,format=v1,context=hypervisor,\
context-range=0xffff82d040000000:0x6b1198,context-unmatched=keep,\
exec-mapping=on
```

This discovery policy increases trace volume, but it lets the analyzer recover
early Xen execution before its physical placement is known.

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

## Automatic image attribution

`qemu-etrace --auto-map` retains unresolved version 1 executions sparsely by
TB, context, vCPU, and dispatched prefix. It resolves them using, in order:

1. an explicit `--address-map` or a virtual range already belonging to the ELF,
   checking captured code against the ELF when available;
2. physical mappings learned from a byte-verified linked TB, with full
   containment and matching bytes at the resulting linked address.

An exact code sequence that occurs only once in the ELF's executable sections
is an unverified candidate. It does not credit coverage or create a physical
binding: another image can contain the same bytes. Candidates remain pending
until independent address-mapping evidence resolves them. End-of-input
diagnostics count the remaining unverified candidate TB definitions in both
aggregate and ordered modes.

Linked-address anchors assume the selected trace address space belongs to the
input ELF at those virtual addresses. Explicit maps assert the corresponding
runtime ownership. Physical bindings cover only the byte-verified TB spans;
they do not establish ownership of an adjacent entry, a whole page, or a load
segment. Version 1 has no image-instance lifetime or page-reuse records, so
these anchors require a stable image mapping. A privilege flag or a matching
byte sequence alone cannot establish that contract for mixed-image traces.

Captured code that contradicts an explicit or linked-address mapping leaves
the TB unresolved. TBs without captured code can use those address mappings
for coverage, but cannot seed physical bindings. There is no minimum code
length for verification at an established address, including short entries.

Once a definition resolves, pending execution aggregates are replayed through
the normal execution-range coverage path. Repeated executions with the same
prefix are combined without changing coverage counts or accumulated duration.
This preserves line and function coverage, but not the original ordering of
unresolved TBs; chronological branch reconstruction will need an ordered spill
or event log rather than this aggregate mode.

Add `--preserve-order` to use that disk-backed event log. The first pass learns
all available image bindings while appending TB executions, context gaps, and
discontinuities to an ordered journal. A second pass replays those records in
their original stream order:

```sh
qemu-etrace --trace xen.etrace --elf xen-syms.debug \
    --auto-map --preserve-order ...
```

The default journal uses an automatically removed temporary file. Select a
retained file with `--event-spool=PATH` and bound journal growth with
`--event-spool-limit=BYTES`; the default limit is 1 GiB. Limit or I/O failures
abort conversion without producing coverage.

The journal uses bounded, lossless compressed frames. The storage limit counts
encoded payloads, headers and the terminal integrity record; socket gzip is
independent. `--event-spool-decoded-limit=BYTES` sets a separate limit on
decoded dynamic record bytes (unlimited by default, up to the 64-bit counter
range). Capture and replay report progress every 64 MiB of logical records,
including execution/gap/discontinuity counts. Final diagnostics report logical
and stored sizes, frame counts, and the verified SHA-256 of the original
dynamic record stream. See [event-journal.md](event-journal.md) for the codec
and buffer accounting. Incomplete final producer status remains fatal before
replay, and journal integrity failure prevents coverage output.

Resolved executions retain their original per-vCPU sequence and stream
interleaving. An execution which remains unresolved is emitted as a `U`
boundary, so future branch analysis can reset predecessor state instead of
connecting control flow across missing code. The ordering is the producer's
serialized observation order; it does not invent a global guest-causal order
for MTTCG.

Ordered mode preserves chronology and individual executions. Aggregate mode
remains preferable when only line/function coverage is needed because it uses
less disk I/O.

`--unresolved-limit=N` bounds the number of distinct pending execution
aggregates; the default is 65536. Exceeding it fails conversion rather than
silently losing possible hypervisor coverage. Definitions and code bytes are
still retained by the normal TB dictionary. Ambiguous or unrelated TBs remain
unresolved and are reported at end of input without being attributed to the
ELF.

Code bytes validate a mapping's contents, independently of the evidence for
image ownership. The 64-bit FNV-1a hash in a TB definition is a stable lookup
aid and is verified by the reader; neither matching hashes nor equal bytes
alone establish image identity.

## Compatibility

Version 0 readers reject version 1 at the information record. This is required
for filtered traces: an old reader must not silently treat an intentionally
partial trace as complete coverage.

The version 1 final status extends the version 0 prefix with filtered-execution,
context-error, mapping-error, and code-error counters. Filtering itself is not
an error; context, mapping, or code-capture failures are.
