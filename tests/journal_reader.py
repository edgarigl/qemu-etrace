"""Independent decoder for the documented internal journal container."""
import hashlib
import struct
import zlib


def decode_journal(data):
    magic, frame_size, reserved = struct.unpack_from("<8sII", data)
    assert (magic, frame_size, reserved) == (b"ETJRNL01", 65536, 0)
    offset = 16
    frames = []
    while True:
        stored, decoded, crc, encoding = struct.unpack_from("<IIII", data, offset)
        offset += 16
        if encoding == 2:
            assert (stored, decoded, crc) == (0, 0, 0)
            logical, count, digest = struct.unpack_from("<QQ32s", data, offset)
            assert offset + 48 == len(data)
            result = b"".join(frames)
            assert logical == len(result)
            assert count == len(frames)
            assert digest == hashlib.sha256(result).digest()
            return result
        assert 0 < stored <= frame_size and 0 < decoded <= frame_size
        payload = data[offset:offset + stored]
        assert len(payload) == stored
        assert zlib.crc32(payload) == crc
        offset += stored
        if encoding == 0:
            frame = payload
        else:
            assert encoding == 1
            stream = zlib.decompressobj()
            frame = stream.decompress(payload)
            assert stream.eof and not stream.unused_data
        assert len(frame) == decoded
        frames.append(frame)
