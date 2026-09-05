# Variable-length instructions

## Symptom

Four-byte coverage buckets can mark the wrong x86 instruction or omit short
instructions. Rounding a TB start down can mark a preceding source line, while
rounding its length down can omit instructions at the end.

## Handling

qemu-etrace stores coverage counters and DWARF locations at byte granularity.
Every byte in the ETrace half-open execution range `[start,end)` is marked, and
source lines are looked up at their exact DWARF addresses. No instruction
disassembly or architecture-specific width is required.

The binary ETrace format already records exact start and end addresses, so this
handling does not require a format version change and applies when reprocessing
existing traces.

## Regression coverage

`tests/test_variable_length_coverage.py` builds an unaligned x86 function with
one-, two-, and four-byte instructions. It verifies short TBs, exact boundary
attribution, the final instruction in an unaligned TB, entry and source function
policies, and byte-addressed textual ETrace coverage.
