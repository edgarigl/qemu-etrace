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

Use `exec=tb` when lower overhead is more important and label its line coverage
as optimistic around synchronous exceptions. Use the QEMU plugin's
`exec=insn` mode for exception-sensitive investigations:

```sh
qemu-system-aarch64 ... \
    -plugin libqemu-etrace.so,out=/tmp/elog,exec=insn
```

Instruction mode emits one exact half-open range for every instruction callback
that QEMU delivers. It establishes dispatch rather than architectural
retirement: the faulting instruction might not complete, and QEMU may omit its
normal instruction callback on some exception paths.
