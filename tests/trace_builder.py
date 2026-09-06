import struct


ETRACE_TYPE_INFO = 0x4554
ETRACE_TYPE_ARCH = 5
ETRACE_TYPE_EXEC = 1
ETRACE_TYPE_TB = 2
ETRACE_TYPE_OLD_EVENT_U64 = 7
ETRACE_TYPE_DISCONTINUITY = 9
ETRACE_TYPE_STATUS = 10
ETRACE_TYPE_TB_DEF = 11
ETRACE_TYPE_TB_EXEC = 12
ETRACE_TYPE_CONTEXT = 13
ETRACE_TYPE_CONTEXT_GAP = 14
ETRACE_INFO_F_FINAL_STATUS = 1 << 1
ETRACE_INFO_F_CONTEXT = 1 << 3
ETRACE_INFO_F_FILTERED = 1 << 4
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


def etrace_status(*, unresolved_tb_exits=0, unresolved_discontinuities=0,
                  unresolved_vcpu_exits=0, output_errors=0,
                  discontinuity_pc_mismatches=0, flags=1, extension=b""):
    payload = struct.pack(
        "=QQQQQII",
        unresolved_tb_exits,
        unresolved_discontinuities,
        unresolved_vcpu_exits,
        output_errors,
        discontinuity_pc_mismatches,
        flags,
        0,
    )
    return etrace_packet(ETRACE_TYPE_STATUS, payload + extension)


def etrace_status_v1(*, filtered_execs=0, context_errors=0,
                     mapping_errors=0, **kwargs):
    extension = struct.pack(
        "=QQQ", filtered_execs, context_errors, mapping_errors
    )
    return etrace_status(extension=extension, **kwargs)


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


def etrace_tb_def(*, tb_id=1, vaddr=0x1000, context_id=0,
                  code_hash=0, size=None, insns=((0, 4),), mappings=(),
                  code=b"", flags=0, reserved=0, extension=b""):
    if size is None:
        size = max((offset + insn_size for offset, insn_size in insns),
                   default=0)
    payload = struct.pack(
        "=QQQQIIHHII",
        tb_id,
        vaddr,
        context_id,
        code_hash,
        size,
        len(code),
        len(insns),
        len(mappings),
        flags,
        reserved,
    )
    payload += b"".join(
        struct.pack("=IHH", offset, insn_size, 0)
        for offset, insn_size in insns
    )
    payload += b"".join(
        struct.pack("=IIQ", offset, length, paddr)
        for offset, length, paddr in mappings
    )
    return etrace_packet(ETRACE_TYPE_TB_DEF, payload + code + extension)


def etrace_tb_exec(*, tb_id=1, sequence=0, time=0, context_id=0,
                   duration=0, insn_count=1, flags=0, extension=b"",
                   unit_id=0):
    payload = struct.pack(
        "=QQQQIHH",
        sequence,
        time,
        tb_id,
        context_id,
        duration,
        insn_count,
        flags,
    )
    return etrace_packet(
        ETRACE_TYPE_TB_EXEC,
        payload + extension,
        unit_id=unit_id,
    )


def etrace_context(*, context_id=1, pc=0x1000, address_space_id=0,
                   virtual_machine_id=0, state_hash=0, flags=0,
                   architecture=0, privilege=0xff, registers=(),
                   reserved=0, extension=b"", unit_id=0):
    payload = struct.pack(
        "=QQQQQIHBBI",
        context_id,
        pc,
        address_space_id,
        virtual_machine_id,
        state_hash,
        flags,
        architecture,
        privilege,
        len(registers),
        reserved,
    )
    for name, value, reg_flags in registers:
        encoded_name = name.encode("ascii")
        payload += struct.pack("=HHI", len(encoded_name), len(value), reg_flags)
        payload += encoded_name + value
    return etrace_packet(
        ETRACE_TYPE_CONTEXT,
        payload + extension,
        unit_id=unit_id,
    )


def etrace_context_gap(*, sequence=1, from_context_id=0, to_context_id=0,
                       filtered_execs=1, reason=1, flags=0, unit_id=0,
                       extension=b""):
    payload = struct.pack(
        "=QQQQII",
        sequence,
        from_context_id,
        to_context_id,
        filtered_execs,
        reason,
        flags,
    )
    return etrace_packet(
        ETRACE_TYPE_CONTEXT_GAP,
        payload + extension,
        unit_id=unit_id,
    )


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
