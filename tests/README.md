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

The plugin unit tests use local API stubs for QEMU plugin API versions 1, 5,
and 7, covering QEMU 8.2, QEMU 10.2, and the callback ABI used by current
upstream QEMU. They verify raw and gzip-compressed output without requiring a
QEMU source tree or emulator binary.

Build tests verify that system Binutils is the default, local Binutils adds its
own include and library paths, and external programs are found through `PATH`.
The staged-install test also runs the installed `etrace-view` launcher against
its installed Python modules.

The x86 variable-length fixture uses explicit instruction encodings and DWARF
line records. Its tests verify byte-precise line and function coverage for
short and unaligned translation blocks, as well as the textual ETrace coverage
output.

Run only the Python integration tests after building `qemu-etrace` with:

```sh
python3 -m pytest -q
```
