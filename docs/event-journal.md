# Internal ordered journal

The internal journal stores the original dynamic record bytes in bounded
frames. It is independent of the ETrace wire format and of socket gzip.
Compression does not aggregate, filter, or reorder executions.

The version 1 container uses little-endian integers. Its 16-byte file header
contains the eight bytes `ETJRNL01`, a 32-bit decoded frame capacity (65536),
and a zero 32-bit reserved field. Each frame has four 32-bit fields:

| Field | Meaning |
|---|---|
| Stored length | Encoded payload bytes following the frame header |
| Decoded length | Original bytes in this frame, at most 65536 |
| CRC32 | Checksum of the stored payload, including compressed padding bits |
| Encoding | 0 for raw bytes, 1 for a complete zlib stream, 2 for the terminator |

The writer uses zlib level 1 and stores raw bytes when compression would
increase the payload size. Frames can split a record anywhere; concatenating
their decoded payloads reconstructs the original byte stream exactly.

The terminal frame has zero lengths and CRC32. Its 48-byte payload contains
the total decoded byte count, the frame count (both 64-bit), and the 32-byte
SHA-256 of the original byte stream. The reader requires this terminal record,
checks the decoded digest and counts against both the terminal payload and
the writer's retained values, and rejects trailing bytes. This catches a
missing suffix and reordered intact frames as well as individual frame damage.

The stored-byte limit includes the file header, every encoded frame header
and payload, stdio-buffered writes, and a reservation for the 64-byte terminal
record. Each complete encoded frame is checked against the remaining budget
before either its header or payload is written. No encoded frames are queued
outside that accounting. A limit or I/O error poisons the journal and prevents
successful replay.

The codec retains at most 64 KiB of pending decoded input, plus one bounded
compression workspace. Pending decoded bytes are reported separately from
stored bytes; their final compressed size is checked when the frame is
encoded. This means a storage-limit failure can occur during the final frame
flush. The independent decoded-byte limit is checked before appending data.
Frame memory and checksum state are bounded regardless of either byte limit.

`tests/unit/test-event-journal.c` covers arbitrary read/write chunk boundaries,
compressible and incompressible data, exact storage/work limits, every
truncation and single-byte corruption in a small journal, frame reordering,
and write failures. The file is an internal diagnostic artifact, not an
ETrace stream that can be passed to `--trace`.
