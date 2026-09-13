# Folded source labels

## Symptom

A source label can have a concrete `DW_TAG_label` / `DW_AT_low_pc` entry
without a corresponding source line-table row. Crediting its declaration
line whenever that PC executes can report a hit for a source path that the
execution bypassed.

## Minimal reproducer

Compile this as `labels.c` with GCC, without coverage instrumentation:

```c
__attribute__((noinline)) int shared(int x)
{
    if (x)
        goto second;
first:
    return x + 2;
second:
    return x + 2;
}
```

```sh
gcc -O2 -g -c labels.c -o labels.o
objdump -dr labels.o
dwarfdump -i labels.o
dwarfdump -l labels.o
```

## Evidence

In the tested x86-64 GCC 14.2 build, `shared` reduces to `lea; ret`, with
an `endbr64` prefix under the toolchain defaults. AArch64 GCC 13.3 similarly
emits a single arithmetic result and return. Both builds retain a `first`
label DIE with a real address in the shared code; `second` has no address.
The linked executable exhibits the same association.

Calling `shared(1)` skips `first` in the source but executes the address
associated with `first` in DWARF. Checking that the label has an address,
belongs to the right function, and refers to executable code does not rule
out this counterexample. Compiler versions and flags may produce different
metadata; the example disproves a general attribution rule, not every
possible label mapping.

## Expected handling

Neither `address` nor `function-entry` line policy promotes label DIEs to
source hits. The latter propagates only a verified subprogram declaration
line using the selected function-hit policy. Existing line-table aliases
still follow the address-based rule; that metric is not proof of a unique
source path.

Use `--coverage-attribution` to inspect the line ranges, columns,
discriminators, statement markers, and counts that the analyzer actually
uses. This diagnostic does not contain label DIE records.

## Safety interpretation

Source identity can be lost by optimization even when a concrete debug
address survives. Do not automatically credit labels, returns, or eliminated
statements merely because their surviving shared code executes. Compiler CFG
and RTL dumps can explain the folding but cannot recover a runtime source
choice when both choices have the same PC sequence. Such cases need stronger
evidence or must remain ambiguous.
