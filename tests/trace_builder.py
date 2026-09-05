import struct


ETRACE_TYPE_INFO = 0x4554
ETRACE_TYPE_ARCH = 5
ETRACE_TYPE_EXEC = 1
ETRACE_TYPE_TB = 2
ETRACE_TYPE_OLD_EVENT_U64 = 7
ETRACE_TYPE_DISCONTINUITY = 9
QEMU_SIMPLE_HEADER_EVENT_ID = (1 << 64) - 1
QEMU_SIMPLE_DROPPED_EVENT_ID = (1 << 64) - 2
QEMU_SIMPLE_HEADER_MAGIC = 0xF2B177CB0AA429B4
QEMU_SIMPLE_HEADER_VERSION = 4
QEMU_SIMPLE_RECORD_MAPPING = 0
QEMU_SIMPLE_RECORD_EVENT = 1


def etrace_info(*, attributes=0, major=0, minor=0):
    payload = struct.pack("=QHH", attributes, major, minor)
    return etrace_packet(ETRACE_TYPE_INFO, payload)


def etrace_packet(packet_type, payload, *, unit_id=0):
    return struct.pack("=HHI", packet_type, unit_id, len(payload)) + payload


def etrace_old_event(*, time, value, unit_id, device, event):
    device_name = device.encode("utf-8") + b"\0"
    event_name = event.encode("utf-8") + b"\0"
    payload = struct.pack(
        "=QQHHH",
        time,
        value,
        unit_id,
        len(device_name),
        len(event_name),
    )
    return etrace_packet(
        ETRACE_TYPE_OLD_EVENT_U64,
        payload + device_name + event_name,
    )


def etrace_discontinuity(*, from_pc, to_pc, kind, flags=0, unit_id=0,
                         extension=b""):
    payload = struct.pack("=QQII", from_pc, to_pc, kind, flags)
    return etrace_packet(
        ETRACE_TYPE_DISCONTINUITY,
        payload + extension,
        unit_id=unit_id,
    )


def etrace_tb(*, guest_code=b"", host_code=b""):
    payload = struct.pack(
        "=QQQII",
        0x1000,
        0x2000,
        0x3000,
        len(guest_code),
        len(host_code),
    )
    return etrace_packet(ETRACE_TYPE_TB, payload + guest_code + host_code)


def etrace_exec32(*, start_time=0, duration=0, start, end):
    payload = struct.pack("=QIII", start_time, duration, start, end)
    return etrace_packet(ETRACE_TYPE_EXEC, payload)


def etrace_exec64(*, start_time=0, duration=0, start, end):
    payload = struct.pack("=QIQQ", start_time, duration, start, end)
    return etrace_packet(ETRACE_TYPE_EXEC, payload)


def etrace_arch(*, guest_bits=32, guest_big_endian=0,
                host_bits=64, host_big_endian=0):
    payload = struct.pack(
        "=IBBxxIBBxx",
        0,
        guest_bits,
        guest_big_endian,
        0,
        host_bits,
        host_big_endian,
    )
    return etrace_packet(ETRACE_TYPE_ARCH, payload)


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


def qemu_simple_event(event_id, *arguments, timestamp=0, pid=0):
    encoded_arguments = struct.pack(f"={len(arguments)}Q", *arguments)
    length = struct.calcsize("=QQII") + len(encoded_arguments)
    return (
        struct.pack("=Q", QEMU_SIMPLE_RECORD_EVENT)
        + struct.pack("=QQII", event_id, timestamp, length, pid)
        + encoded_arguments
    )
