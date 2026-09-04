# Tests

Run the complete test suite with:

```sh
make check
```

The suite uses GLib's test API for C unit tests and pytest for command-line
and trace-format integration tests. Trace fixtures are generated at runtime
using the native byte order consumed by the decoders.

Run only the Python integration tests after building `qemu-etrace` with:

```sh
python3 -m pytest -q
```
