# Tests

Run the complete test suite with:

```sh
make check
```

The suite uses GLib's test API for C unit tests and pytest for command-line
and trace-format integration tests. Trace fixtures are generated at runtime
using the native byte order consumed by the decoders.

Address-map tests cover parsing, overlap and overflow validation, boundary
splitting, all trace input backends, gzip input, and both function-hit policies.

`test_gcc_matrix.py` discovers installed native `gcc-N` binaries and rebuilds
the inline-function fixture with each distinct compiler. It verifies both
inline-entry attribution and rejection of execution that starts in a later
inline-attributed block.

The plugin unit tests use local API stubs for QEMU plugin API versions 1, 2, 4,
5, 6, and 7. API versions 2 and 4 cover register-aware releases before the
virtual-address translation API, API version 5 is built both with and without
the discontinuity callback to cover QEMU 10.1 and 10.2, version 6 covers QEMU
11.0, and version 7 covers the callback ABI used by current upstream QEMU. The
tests verify raw and gzip-compressed output, repeated virtualization-style
transitions, context changes, and final producer status without requiring a
QEMU source tree or emulator binary.

Build tests verify that system Binutils is the default, local Binutils adds its
own include and library paths, and external programs are found through `PATH`.
The staged-install test also runs the installed `etrace-view` launcher against
its installed Python modules.

The x86 variable-length fixture uses explicit instruction encodings and DWARF
line records. Its tests verify byte-precise line and function coverage for
short and unaligned translation blocks, as well as the textual ETrace coverage
output.

The x86 assembly-attribution fixture covers adjacent DWARF line sequences,
leading bytes without source rows, repeated line mappings, macro-generated
functions, zero-sized labels and functions, and linker-discarded executable
sections. It also verifies JSON Lines function-inventory diagnostics.

`test_coverage_attribution.py` checks JSON Lines DWARF evidence from an
uninstrumented assembly fixture: columns, discriminators, statement markers,
equal-address aliases, partial counts, discarded code, exclusions, output
errors, and unchanged LCOV reports with the diagnostic enabled.

`test_gcc_provenance.py` checks the optional research return-block audit with
uninstrumented x86 GCC fixtures. It requires pyelftools and an x86 objdump;
runtime-witness tests additionally use qemu-x86_64. See
`research/gcc-provenance.md` for supported artifacts and attribution limits.

`test_gcc_return_origins.py` probes pre-CFG GIMPLE versus merged CFG returns
with optional x86 GCC 13/14 builds and direct/thunk returns. It covers macro
expansion, same-line origins, dead returns, and explicit/implicit exits;
real QEMU runs demonstrate source paths with identical PC sequences. The
fixed-fixture extractor is not a general source-provenance parser. See
`research/gcc-return-origins.md` for evidence-retention instructions.

`tests/xen_assembly_validation.py` validates a regenerated report from the
retained Xen x86 audit. The multi-gigabyte trace is intentionally not part of
the normal test suite; its checked summary is stored in
`tests/fixtures/xen-assembly-validation.json`.

Run only the Python integration tests after building `qemu-etrace` with:

```sh
python3 -m pytest -q
```
