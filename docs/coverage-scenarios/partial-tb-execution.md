# Partial translation-block execution

## Symptom

ETrace marks instructions near the end of a translated block as hit even though
a synchronous exception stopped execution earlier.

## Explanation

The default QEMU plugin records translation-block entry. A block-entry callback
proves that the first instruction was dispatched, but it does not prove that
every instruction in the translated range completed. Synchronous exceptions
can leave the block early.

## Expected handling

Use TB-level tracing for normal coverage because of its lower overhead. Use a
future instruction-level plugin mode for exception-sensitive investigations,
and label TB-derived line coverage as conservative.
