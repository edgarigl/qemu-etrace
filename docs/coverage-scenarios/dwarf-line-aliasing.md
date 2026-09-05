# DWARF line aliasing

## Symptom

One machine address is attributed to multiple source lines or to a source file
that differs from the enclosing ELF symbol's source file.

## Explanation

Inlining, macros, compiler-generated code, and adjacent line-table sequences
can create multiple DWARF locations for one address. A simple address-to-line
lookup is therefore not one-to-one.

## Expected handling

Retain every location associated with an address and preserve inline-stack
identity where available. Compare coverage by normalized source identity rather
than assigning every line to the enclosing ELF symbol.
