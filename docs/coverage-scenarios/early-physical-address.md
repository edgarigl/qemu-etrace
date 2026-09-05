# Early physical execution

## Symptom

GCOV reports early boot or EFI code as hit while ETrace cannot associate the
executed addresses with linked ELF symbols.

## Explanation

Early code can run at temporary physical or identity-mapped addresses. The ELF
symbol and DWARF tables describe the final linked virtual addresses, so direct
address lookup misses even though the code executed.

## Expected handling

Record or configure the physical-to-virtual relocation and normalize execution
addresses before symbol and line lookup. Do not classify the mismatch as dead
code until that mapping is available.
