# Coverage scenarios

This directory records cases where machine execution and source coverage have
non-obvious relationships. Each scenario should include:

- the observed coverage difference;
- a minimal reproducer or exact build context;
- relevant ELF, disassembly, and DWARF evidence;
- the expected result for each qemu-etrace coverage policy;
- the safety interpretation;
- a link to its regression test, when available.

Current scenarios:

- [Inlined body with a dead symbol](inlined-body-with-dead-symbol.md)
- [Shared epilogue in an inline range](shared-epilogue-inline-range.md)
- [Early physical execution](early-physical-address.md)
- [Partial translation-block execution](partial-tb-execution.md)
- [Variable-length instructions](variable-length-instructions.md)
- [DWARF line aliasing](dwarf-line-aliasing.md)
