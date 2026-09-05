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

Run only the Python integration tests after building `qemu-etrace` with:

```sh
python3 -m pytest -q
```
