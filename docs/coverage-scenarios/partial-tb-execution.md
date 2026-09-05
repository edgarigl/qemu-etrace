# Partial translation-block execution

## Symptom

An optimistic translation-block-entry trace can mark instructions near the end
of a translated block as hit even though a synchronous exception stopped
execution earlier.

## Explanation

The affected plugin implementation recorded a complete translated range at
translation-block entry. A block-entry callback proves that execution entered
the block, but it does not prove that every instruction in the translated
range completed. Synchronous exceptions can leave the block early.

## Expected handling

The QEMU plugin always emits accurate ranges. API version 1 emits one range for
each instruction callback. Newer APIs delay TB ranges until they are resolved,
using one terminal-instruction marker per TB when system-emulation
discontinuities are available and a per-instruction inline progress marker as
the compatibility fallback.

The trace establishes dispatch rather than architectural retirement. A
faulting instruction might not complete and remains represented by its
discontinuity rather than being included in the ordinary completed prefix.
