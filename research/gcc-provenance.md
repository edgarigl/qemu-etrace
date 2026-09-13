# GCC return-block provenance experiment

`gcc_provenance.py` is a build-time diagnostic for GCC x86-64 artifacts, not
an analyzer input or coverage policy. It derives machine return-block mappings
and keeps source association and runtime observation explicitly unresolved.
It requires Python 3.11+, pyelftools, and an x86-capable GNU objdump; these are
optional research dependencies, not qemu-etrace runtime requirements.

## Collect and audit

Keep the project's normal compilation flags. Append diagnostic flags for the
selected translation unit, with a unique assembler listing path:

```sh
gcc ... -c source.c -o source.o \
    -save-temps=obj -dA -dp -fverbose-asm -fdump-rtl-final \
    -Wa,-adhln=source.lst
```

Link the resulting object normally and retain the exact executable. Verify
executable bytes against a control build without diagnostic flags. Do not
enable GCOV instrumentation for this workflow. Use saved assembly instead of
`-pipe`, which can remove comments from listings.

```sh
python3 research/gcc_provenance.py \
    --assembly source.s --listing source.lst --rtl source.c.353r.final \
    --object source.o --elf program --function selected_function \
    --objdump x86_64-linux-gnu-objdump
```

Use the actual final-dump filename; GCC pass numbers vary. JSON is written to
stdout only after all checks pass. The tool does not modify its inputs.

## What is verified

The diagnostic scopes final RTL instruction IDs and saved-assembly block IDs
to one function. It joins each emitted return-block instruction to its listing
line and full bytes, including continuation rows, and to an object instruction
boundary decoded by objdump. It verifies contiguous block instructions and
checks that annotated RTL IDs belong to the matching block.

GCC's external-return-thunk jump can lack a `-dp` instruction comment. In that
case the tool requires exactly one RTL return in the block, a supported return
encoding at the block terminator, and an ELF relocation to
`__x86_return_thunk`. This special correspondence is not applied to arbitrary
unannotated instructions or tail calls.

Linked placement is anchored by the uniquely named function symbol in the
object and executable, with bounds checks and PC32/PLT32 relocation validation
against exact linked bytes. It does not claim to validate a linker map. It
records SHA-256 identities for every input; retain the compiler version,
complete build commands, source/configuration, and parent manifest alongside
the result. A list of hashes is not itself proof that independently supplied
files came from the same build.

The prototype targets the tested GCC 14 x86-64 textual formats. It requires
an ET_REL object and ET_EXEC executable. LTO, linker relaxation, folded or
ambiguous symbols, inline assembly in return blocks, unsupported relocations,
and incomplete listings are outside its supported scope. It does not provide
a complete function CFG or claim to enumerate every possible machine exit.

## Source identity is a separate obligation

`statement_notes` and `predecessor_text` are compiler metadata, not source-hit
proof. An incoming edge's location does not apply to every other predecessor.
A final compiler return may combine several original source returns. Neither
one final return nor a nearby statement note proves one source origin.

All records therefore have `source_association: unresolved`,
`execution: not-observed`, and `coverage_candidate: false`. A manually checked
single-source-return premise may be documented separately, bound to the exact
source and preprocessed input. Do not silently turn it into an automated rule
or borrow execution counts from an instrumented/different ELF.

The return instruction, not the start of the epilogue, is the address witness.
`witness_observed()` requires its entire byte interval within one execution
range. Its caller must establish exact ELF/context ownership first. This
means instruction dispatch, not retirement or proof that the callee returned
successfully. Partial or unrelated byte observations must not be stitched
together into a return event.

## Regression coverage

`tests/test_gcc_provenance.py` builds uninstrumented fixtures with direct
returns and external return thunks. It checks unchanged executable sections,
multiple epilogues, folded returns, branchless return choices, truncated
execution, inconsistent RTL/listing/ELF inputs, and unchanged LCOV output.
When qemu-x86_64 is available, real one-instruction-per-TB logs verify return
witnesses and identical PC sequences for different branchless outcomes.
Those runs are user-mode fixtures, not an uninstrumented Xen IOCHK run.

The retained Xen block-7 study, its separate source premise, and synthetic
accounting results are described in [gcc-provenance-block7.md](gcc-provenance-block7.md).
