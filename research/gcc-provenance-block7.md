# Uninstrumented Xen return-block follow-up

This experiment uses the retained Xen compiler-provenance bundle for commit
`60e075676b32410ab407a437d7e4f581d236a561`, compiled with x86-64 GCC 14.2.0.
The diagnostic is described in [gcc-provenance.md](gcc-provenance.md).
No coverage policy or qemu-etrace runtime code is changed.

## Derived machine evidence

The audit derives both `pin_2_irq()` return blocks from final RTL, saved
assembly, listings, object instructions, and relocations. Block IDs, offsets,
and RTL IDs are not supplied to the audit. The linked uninstrumented ELF has
SHA-256 `78ff13e8ddcd864873fd039202c2b112c710d881c9a1c9359a6d284c476b87c9`.

| Evidence | Block 7 | Block 13 (control) |
|---|---|---|
| Object section | `.text.pin_2_irq` | `.text.pin_2_irq` |
| Object interval | `[0x49,0x54)` | `[0x8b,0x98)` |
| Linked interval | `[0xffff82d040264ca9,0xffff82d040264cb4)` | `[0xffff82d040264ceb,0xffff82d040264cf8)` |
| Return witness | `[0xffff82d040264caf,0xffff82d040264cb4)` | `[0xffff82d040264cf3,0xffff82d040264cf8)` |
| RTL instruction IDs | 184, 185, 186, 187 | 196, 107, 197, 198, 199 |
| Predecessors | 16, 6, 10 | 12 |
| Line 1014 aliases the witness | No | Yes |

Block 7's instruction bytes are checked against the linked ELF after applying
the PC-relative relocation to `__x86_return_thunk`. Its local statement-note
list is empty. One incoming edge has a line-1014 location, but the other
predecessors cannot inherit that location just because they share an exit.

Block 13 already has a DWARF alias for line 1014 on the return tail. Its
line-1014 statement note does not demonstrate additional source coverage
beyond the existing alias-preserving line policy.

## Separate source premise

Manual review of the exact original and preprocessed `pin_2_irq()` bodies
finds one explicit `return irq;`, at source line 1014. The switch arms assign
`irq` and converge on this return. The preprocessed body contains no additional
macro-expanded return. Assuming faithful compilation and normal generated
control flow, a normal exit from this function corresponds to that source
return. Non-returning calls supply no normal-exit witness.

This premise is bound to the original source SHA-256
`eed67ff767f5b5798d6720f4d0b0c535a5304d65135837d9c1410e5c1eee0223`
and preprocessed-input SHA-256
`1dd983f901fb960660ed8c4ef73d6cd3d8ee585d39b63c9b9526a3ca296778f9`.
It is not inferred by counting returns in optimized GIMPLE, nor generalized
to other functions. The automated diagnostic still reports source association
as unresolved; the separate experiment records the manually reviewed premise.

## Synthetic accounting result

Synthetic ETrace execution ranges processed against this exact uninstrumented
ELF produce:

| Synthetic input | Return witness observed | Default line 1014 | Default line 1015 |
|---|---|---|---|
| Complete block 7 | Yes | 0 | 1 |
| Block 7 stopping before its thunk jump | No | 0 | 1 |
| Complete block 13 | Yes | 1 | 1 |

Thus block 7 is a meaningful candidate for additional source attribution,
conditional on the separately reviewed premise and a real execution witness.
Observing its prefix cannot stand in for observing the return. These are
synthetic accounting checks, not evidence that Xen executed either block.

Small uninstrumented user-mode fixtures also run under qemu-x86_64 with direct
returns and external return thunks. They exercise multiple return sites and
branchless source choices with identical PC sequences. Six retained runs
(three inputs per return mechanism) observe `single_return()` exit witnesses,
while its source return line is absent from default DWARF/LCOV. The logs are
converted to ETrace ranges using instruction sizes from each exact ELF. This
demonstrates the address witness and missing source coordinate in a real
uninstrumented fixture, with a manually reviewed single-return premise; it is
not an uninstrumented Xen IOCHK execution or a general source-proof algorithm.

## Remaining boundary

No matching uninstrumented Xen runtime trace is retained in the parent bundle.
Do not copy the instrumented run's 150 hits to this ELF. To complete the Xen
runtime experiment, capture a trace from the exact ELF above (or regenerate
all mappings for the new ELF), normalize and validate image ownership, and
check the block-7 return-witness interval. Compare default line 1014 coverage
over that same interval. Keep the proposed association diagnostic-only.

The instrumented comparison function contains other return blocks with
section-symbol relocations outside this narrow audit's support. Its full
function audit is reported as unsupported, not partially accepted as complete.
`spec_ctrl.c:541` remains unresolved; this experiment adds no provenance for it.

The experiment improves byte-mapping validation and isolates a useful manual
source premise. It does not establish an automatic source-provenance rule or
complete the real uninstrumented Xen acceptance criterion. A production
sidecar importer and new coverage policy remain out of scope.

## Retained artifacts

The original hashed bundle is unchanged. The follow-up is at:

```text
/home/edgar/safety/context/etrace-results/zapote-etrace-20260909/compiler-provenance-block7/
```

It contains `reproduce.py`, `uninstrumented-returns.json`,
`instrumented-unresolved.json`, `source-premise.json`, `associations.jsonl`,
`synthetic-regression.json`, synthetic traces and LCOV reports, and a manifest
binding the parent bundle and diagnostic. Reproduce with:

```sh
python3 /path/to/compiler-provenance-block7/reproduce.py \
    --repo /path/to/qemu-etrace --run-analyzer
```

The script regenerates files in the follow-up directory only. Its manual
premise is restricted to the source hashes above. The test suite checks the
general diagnostic separately using newly compiled, uninstrumented fixtures.
