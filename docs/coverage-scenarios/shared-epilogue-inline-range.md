# Shared epilogue in an inline range

## Symptom

DWARF attributes an executed common return block to an inline function even
though control flow jumps around the inline call. Treating any address in the
inline range as a function hit therefore produces a false positive.

The Xen `_read_lock` discrepancy is an example. `addr2line -i` attributes
addresses in the executed range
`0xffff82d0402ad670-0xffff82d0402ad6a2` to `_read_lock`, `read_lock`, and
`hvm_migrate_pirqs`. The branch entering that range is the early return in
`hvm_migrate_pirqs` and bypasses both lock calls.

## Explanation

Compiler-generated epilogues and return blocks can be shared by several source
paths. Their DWARF inline ranges describe source attribution, not proof that
control flow entered each inline instance from its beginning.

The source function policy counts an inline instance only when execution covers
its `DW_AT_entry_pc`. If that attribute is absent, `DW_AT_low_pc` is used as a
conservative fallback. Merely executing a later address in the inline range is
not sufficient.

## Duplicate retained symbols

Header-defined static inline functions can leave several local ELF symbols with
the same source identity. LCOV declarations are deduplicated by normalized
source path, declaration line, and function name. The maximum hit count is used
instead of summing identical records.

## Regression coverage

`tests/test_function_coverage.py` locates multiple addresses attributed to the
same inline instance. It verifies that executing the instance entry produces a
source hit while executing only a later attributed address does not. A second
fixture links two copies of the same static inline definition and verifies that
only one LCOV function record is emitted.

`tests/test_gcc_matrix.py` repeats the entry and shared-tail checks with every
installed native GCC version. The fixture uses a non-trivial conditional body
so GCC versions that omit inline DIEs for trivial expressions still retain the
required inline attribution.
