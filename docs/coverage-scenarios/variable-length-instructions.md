# Variable-length instructions

## Symptom

Coverage attribution on x86 can mark the wrong instruction or omit short
instructions.

## Explanation

The current coverage arrays divide symbol offsets into four-byte buckets. This
matches AArch64 instruction width but not x86, where instruction boundaries and
lengths vary.

## Expected handling

Use instruction boundaries supplied by the QEMU plugin or a disassembler rather
than advancing through a symbol in fixed four-byte increments. Do not describe
x86 results as instruction-precise until this is implemented.
