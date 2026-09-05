# Runtime address maps

Runtime address maps translate loader-selected execution addresses into the
virtual addresses used by a linked ELF image. They are intended for early boot
and relocation stages where the traced PC does not yet match the addresses in
the ELF symbol and DWARF tables.

## Command line

Add one option for each mapped range:

```sh
--address-map RUNTIME_START:LINKED_START:SIZE
```

All three values are hexadecimal. For example:

```sh
qemu-etrace \
    --trace xen.elog.gz \
    --elf xen-syms.debug \
    --address-map 0x1d600000:0xffff82d040000000:0x6b1198 \
    --coverage-format lcov \
    --coverage-output xen.info \
    --trace-output none
```

The option is repeatable when an image executes through several relocation
addresses.

## Semantics

Each mapping describes the half-open runtime range:

```text
[runtime_start, runtime_start + size)
```

An address in that range is normalized as:

```text
linked = runtime - runtime_start + linked_start
```

Normalization occurs before symbol lookup, DWARF attribution, line coverage,
and `entry` or `source` function-hit accounting. Unmapped addresses retain
their recorded values.

Mappings are sorted by runtime address. Overlapping mappings are accepted only
when they produce the same translation throughout the overlap. Zero-sized,
malformed, conflicting, and overflowing mappings are rejected.

An execution range crossing a mapping boundary is split into mapped and
unmapped segments. A nonzero duration is divided proportionally between the
segments while preserving the original total.

## Trace output

The input trace is never rewritten. A normalized decoded record includes both
address ranges:

```text
E0 runtime=1d95e920-1d95e924 linked=ffff82d04035e920-ffff82d04035e924 efi_arch_cpu
```

Records that do not require normalization keep the original output format.

## Streaming

Explicit maps work identically with regular files, gzip files, standard input,
and `unix:` sockets. No look-ahead, rewind, or sidecar metadata is required.

Automatic virtual-to-physical inference is intentionally outside this initial
implementation. It can be added later without changing explicit map semantics.
