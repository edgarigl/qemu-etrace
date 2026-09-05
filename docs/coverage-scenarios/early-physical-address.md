# Early physical execution

## Symptom

GCOV reports early boot or EFI code as hit while ETrace cannot associate the
executed addresses with linked ELF symbols.

## Explanation

Early code can run at temporary physical or identity-mapped addresses. The ELF
symbol and DWARF tables describe the final linked virtual addresses, so direct
address lookup misses even though the code executed.

## Expected handling

Configure the physical-to-virtual relocation explicitly and normalize execution
addresses before symbol and line lookup:

```sh
--address-map 0x1d600000:0xffff82d040000000:0x6b1198
```

The option also works for UNIX-socket input because the map is known before the
first execution record arrives. Do not classify the mismatch as dead code until
the required mapping is available.
