"""Audit GCC x86-64 return blocks; never infer source coverage.

Experimental build-time diagnostic, not a sidecar importer. Requires
pyelftools and an x86-capable GNU objdump. GCC text formats are not stable.
Unknown, incomplete, or inconsistent mappings fail closed.
"""

import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess

from elftools.elf.elffile import ELFFile
from elftools.common.exceptions import ELFError


class AuditError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise AuditError(message)


def identity(path):
    with Path(path).open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    return {"path": str(Path(path).resolve()), "sha256": digest}


def rtl_function(text, function):
    headers = list(re.finditer(r"^;; Function (\S+) .*", text, re.M))
    matches = [i for i, match in enumerate(headers) if match[1] == function]
    require(len(matches) == 1, "RTL function is missing or ambiguous")
    index = matches[0]
    end = headers[index + 1].start() if index + 1 < len(headers) else len(text)
    body = text[headers[index].end():end]
    instructions, notes = {}, {}
    entries = list(re.finditer(r"^\((?:insn|jump_insn|call_insn|note)\b", body, re.M))
    for i, entry in enumerate(entries):
        stop = entries[i + 1].start() if i + 1 < len(entries) else len(body)
        record = body[entry.start():stop]
        header = re.match(
            r"\((insn|jump_insn|call_insn|note)(?:/[a-z]+)?(?::\w+)? "
            r"(\d+) \d+ \d+ (\d+) (.*)", record,
        )
        if not header:
            continue
        kind, uid, block, rest = header.groups()
        uid, block = int(uid), int(block)
        if kind == "note":
            location = re.match(r"(.*):(\d+) NOTE_INSN_BEGIN_STMT\)", rest)
            if location:
                notes.setdefault(block, []).append({
                    "source": location[1], "line": int(location[2]), "rtl_uid": uid,
                })
        else:
            require(uid not in instructions, "duplicate RTL instruction ID")
            instructions[uid] = {
                "block": block,
                "return": kind == "jump_insn" and bool(
                    re.search(r"\((?:simple_return|return)\)", record)),
            }
    require(instructions, "no supported RTL instructions")
    return instructions, notes


def listing_rows(text):
    rows = {}
    current = None
    for line in text.splitlines():
        match = re.match(r"^\s*(\d+) +([0-9a-fA-F]{4,16}) +"
                         r"([0-9a-fA-F]+) *\t(.*)$", line)
        if match:
            number, address, encoded, source = match.groups()
            current = [int(address, 16), bytes.fromhex(encoded), source.strip()]
            rows.setdefault(int(number), []).append(current)
            current_number = int(number)
        else:
            continuation = re.match(r"^\s*(\d+) +([0-9A-Fa-f]+)\s*$", line)
            if continuation and current is not None and int(continuation[1]) == current_number:
                current[1] += bytes.fromhex(continuation[2])
            elif line.strip():
                current = None
    return rows


def assembly_blocks(text, function):
    lines = text.splitlines()
    starts = [i for i, line in enumerate(lines) if line == function + ":"]
    require(len(starts) == 1, "assembly function is missing or ambiguous")
    section, current, blocks = None, None, {}
    active = False
    for number, line in enumerate(lines, 1):
        stripped = line.strip()
        match = re.match(r"\.section\s+([^,\s]+)", stripped)
        if match:
            section = match[1]
        elif stripped == ".text":
            section = ".text"
        if number == starts[0] + 1:
            active = True
        if not active:
            continue
        if re.match(r"\.size\s+" + re.escape(function) + r"\s*,", stripped):
            return blocks
        match = re.match(r"# BLOCK (\d+),", stripped)
        if match:
            block = int(match[1])
            require(block not in blocks, "duplicate assembly block ID")
            current = blocks[block] = {
                "instructions": [], "predecessors": [], "predecessor_text": None,
            }
        elif current is not None:
            if stripped.startswith("# PRED:"):
                current["predecessor_text"] = stripped[7:].strip()
                current["predecessors"] = re.findall(
                    r"(?<!\S)(ENTRY|\d+)\s+\[", stripped[7:])
            elif stripped and not stripped.startswith((".", "#")):
                if not stripped.endswith(":"):
                    current["instructions"].append((number, section, line))
            elif stripped.startswith("#APP"):
                current["unsupported_asm"] = True
    raise AuditError("assembly function has no size boundary")


def disassemble(objdump, path, section):
    result = subprocess.run(
        [objdump, "-d", "-w", "-j", section, str(path)],
        text=True, capture_output=True, check=True,
    )
    instructions = {}
    for line in result.stdout.splitlines():
        match = re.match(r"^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2} )+)\s*(.*)", line)
        if match:
            instructions[int(match[1], 16)] = (bytes.fromhex(match[2]), match[3])
    require(instructions, "objdump returned no instructions")
    return instructions


def unique_symbol(elf, name):
    table = elf.get_section_by_name(".symtab")
    require(table is not None, "ELF has no symbol table")
    matches = [symbol for symbol in table.iter_symbols()
               if symbol.name == name and isinstance(symbol["st_shndx"], int)]
    require(len(matches) == 1, f"missing or ambiguous defined symbol: {name}")
    return matches[0]


def linked_bytes(obj, linked, section, function, start, end):
    obj_symbol = unique_symbol(obj, function)
    linked_symbol = unique_symbol(linked, function)
    require(obj_symbol["st_info"]["type"] == linked_symbol["st_info"]["type"] == "STT_FUNC",
            "selected symbols are not functions")
    require(obj.get_section(obj_symbol["st_shndx"]).name == section.name,
            "return block is outside the selected function section")
    require(obj_symbol["st_value"] <= start < end <=
            obj_symbol["st_value"] + obj_symbol["st_size"], "object function bounds")
    base = linked_symbol["st_value"] - obj_symbol["st_value"]
    destination = linked.get_section(linked_symbol["st_shndx"])
    require(destination["sh_flags"] & 6 == 6, "linked section is not executable/allocated")
    require(base + end <= linked_symbol["st_value"] + linked_symbol["st_size"],
            "linked function bounds")
    expected = bytearray(section.data()[start:end])
    relocations = []
    for relsec in obj.iter_sections():
        if relsec["sh_type"] not in ("SHT_REL", "SHT_RELA"):
            continue
        if obj.get_section(relsec["sh_info"]).name != section.name:
            continue
        require(relsec["sh_type"] == "SHT_RELA", "REL relocations are unsupported")
        symbols = obj.get_section(relsec["sh_link"])
        for rel in relsec.iter_relocations():
            off, kind = rel["r_offset"], rel["r_info_type"]
            if off >= end or off + 8 <= start:
                continue
            require(kind in (2, 4), "unsupported relocation near return block")
            if off + 4 <= start:
                continue
            require(start <= off and off + 4 <= end, "partial relocation")
            target = symbols.get_symbol(rel["r_info_sym"]).name
            value = unique_symbol(linked, target)["st_value"] + rel["r_addend"] - (base + off)
            require(-(1 << 31) <= value < (1 << 31), "relocation overflow")
            expected[off - start:off - start + 4] = struct.pack("<i", value)
            relocations.append({"offset": off, "type": kind, "target": target,
                                "addend": rel["r_addend"]})
    offset = base + start - destination["sh_addr"]
    require(0 <= offset and offset + end - start <= destination["sh_size"],
            "linked section bounds")
    actual = destination.data()[offset:offset + end - start]
    require(bytes(expected) == actual, "relocated object bytes differ from linked ELF")
    return base, actual, relocations


def audit_returns(*, assembly, listing, rtl, obj, elf, function, objdump):
    """Return derived machine mappings, without a source-hit inference."""
    assembly, listing, rtl, obj, elf = map(Path, (assembly, listing, rtl, obj, elf))
    rtl_insns, notes = rtl_function(rtl.read_text(), function)
    rows = listing_rows(listing.read_text())
    blocks = assembly_blocks(assembly.read_text(), function)
    records = []
    with obj.open("rb") as object_stream, elf.open("rb") as linked_stream:
        object_elf, linked_elf = ELFFile(object_stream), ELFFile(linked_stream)
        require(object_elf["e_machine"] == linked_elf["e_machine"] == "EM_X86_64",
                "only x86-64 is supported")
        require(object_elf["e_type"] == "ET_REL" and linked_elf["e_type"] == "ET_EXEC",
                "require an object and a fixed-address executable")
        require(not any(s.name.startswith(".gnu.lto_") for s in object_elf.iter_sections()),
                "LTO objects are unsupported")
        decoded = {}
        for block, data in blocks.items():
            returns = [uid for uid, info in rtl_insns.items()
                       if info["block"] == block and info["return"]]
            if not returns:
                continue
            require(len(returns) == 1, "multiple RTL returns in one block")
            require(not data.get("unsupported_asm"), "inline assembly in return block")
            mapped = []
            for number, section, line in data["instructions"]:
                # Listings may truncate comments, but must identify the same
                # assembly line. Include files can reuse listing line numbers.
                candidates = [row for row in rows.get(number, [])
                              if row[2] and line.strip().startswith(row[2])]
                require(len(candidates) == 1, f"missing/ambiguous listing row {number}")
                offset, listing_code, _ = candidates[0]
                if section not in decoded:
                    decoded[section] = disassemble(objdump, obj, section)
                require(offset in decoded[section], "listing offset is not an instruction start")
                code, mnemonic = decoded[section][offset]
                require(code == listing_code, "listing bytes differ from object instruction")
                uid_match = re.search(r"#\s*(\d+)\s+\[c=", line)
                operation = line.strip().split("#", 1)[0].strip()
                is_return = operation in ("ret", "retq", "rep ret", "jmp\t__x86_return_thunk")
                if uid_match:
                    uid = int(uid_match[1])
                    require(uid in rtl_insns and rtl_insns[uid]["block"] == block,
                            "assembly/RTL block or instruction ID mismatch")
                    require(rtl_insns[uid]["return"] == is_return, "return kind mismatch")
                else:
                    require(is_return, "instruction has no RTL identity")
                    uid = returns[0]
                if is_return:
                    require(code in (b"\xc3", b"\xf3\xc3") or
                            (operation.startswith("jmp") and len(code) == 5 and code[0] == 0xe9),
                            "unsupported return encoding")
                mapped.append({"assembly_line": number, "rtl_uid": uid,
                               "section": section, "offset": offset, "size": len(code),
                               "return": is_return, "disassembly": mnemonic})
            require(mapped and mapped[-1]["return"] and
                    sum(item["return"] for item in mapped) == 1, "missing terminal return")
            require(len({item["rtl_uid"] for item in mapped}) == len(mapped), "reused RTL identity")
            for first, second in zip(mapped, mapped[1:]):
                require(first["section"] == second["section"] and
                        first["offset"] + first["size"] == second["offset"],
                        "noncontiguous return block")
            section = object_elf.get_section_by_name(mapped[0]["section"])
            start, end = mapped[0]["offset"], mapped[-1]["offset"] + mapped[-1]["size"]
            base, code, relocations = linked_bytes(object_elf, linked_elf, section,
                                                   function, start, end)
            witness = mapped[-1]
            if code[-witness["size"]] == 0xe9:
                require(any(rel["offset"] == witness["offset"] + 1 and
                            rel["target"] == "__x86_return_thunk" and rel["addend"] == -4
                            for rel in relocations), "return thunk relocation is missing")
            records.append({
                "version": 1, "kind": "gcc-return-block", "function": function,
                "final_block": block, "predecessors": data["predecessors"],
                "predecessor_text": data["predecessor_text"],
                "statement_notes": notes.get(block, []),
                "object_section": section.name, "object_start": hex(start), "object_end": hex(end),
                "linked_start": hex(base + start), "linked_end": hex(base + end),
                "witness_start": hex(base + witness["offset"]), "witness_end": hex(base + end),
                "instructions": mapped, "relocations": relocations,
                "linked_bytes_sha256": hashlib.sha256(code).hexdigest(),
                "byte_mapping": "verified", "source_association": "unresolved",
                "source_reason": "Final blocks/notes do not prove original source-return identity",
                "execution": "not-observed", "coverage_candidate": False,
            })
    require(records, "no supported return blocks")
    inputs = {name: identity(path) for name, path in
              (("assembly", assembly), ("listing", listing), ("rtl", rtl), ("object", obj), ("elf", elf))}
    return {"version": 1, "inputs": inputs, "returns": records}


def witness_observed(record, execution_ranges):
    """Require a whole return instruction within one dispatched range.

    This checks an address witness only, not source identity or retirement.
    Callers must separately establish exact ELF/context ownership of ranges.
    """
    start, end = int(record["witness_start"], 16), int(record["witness_end"], 16)
    return any(low <= start and end <= high for low, high in execution_ranges)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for option in ("assembly", "listing", "rtl", "object", "elf", "function"):
        parser.add_argument("--" + option, required=True)
    parser.add_argument("--objdump", default="objdump")
    args = vars(parser.parse_args())
    args["obj"] = args.pop("object")
    try:
        result = audit_returns(**args)
    except (AuditError, ELFError, OSError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"provenance audit: {error}\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
