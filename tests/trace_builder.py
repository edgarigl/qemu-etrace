import struct


ETRACE_TYPE_INFO = 0x4554
QEMU_SIMPLE_HEADER_EVENT_ID = (1 << 64) - 1
QEMU_SIMPLE_HEADER_MAGIC = 0xF2B177CB0AA429B4
QEMU_SIMPLE_HEADER_VERSION = 4
QEMU_SIMPLE_RECORD_MAPPING = 0


def etrace_info(*, attributes=0, major=0, minor=0):
    payload = struct.pack("=QHH", attributes, major, minor)
    header = struct.pack("=HHI", ETRACE_TYPE_INFO, 0, len(payload))
    return header + payload


def qemu_simple_header():
    return struct.pack(
        "=QQQ",
        QEMU_SIMPLE_HEADER_EVENT_ID,
        QEMU_SIMPLE_HEADER_MAGIC,
        QEMU_SIMPLE_HEADER_VERSION,
    )


def qemu_simple_mapping(event_id, name):
    encoded_name = name.encode("utf-8")
    return (
        struct.pack("=QQI", QEMU_SIMPLE_RECORD_MAPPING, event_id, len(encoded_name))
        + encoded_name
    )
