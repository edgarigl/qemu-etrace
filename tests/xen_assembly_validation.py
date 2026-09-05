import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import subprocess


EXPECTED_ELF_SHA256 = (
    "e1e8dcb0f74ca20b380294c28abeda01da82e1e0d9713ea6488132b3c9149a64"
)


def parse_lcov(path):
    records = {}
    current = None
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        if line.startswith("SF:"):
            current = {"functions": [], "function_hits": {}, "lines": {}}
            records[line[3:]] = current
        elif current is None:
            continue
        elif line.startswith("FN:"):
            line_number, name = line[3:].split(",", 1)
            current["functions"].append((int(line_number), name))
        elif line.startswith("FNDA:"):
            count, name = line[5:].split(",", 1)
            current["function_hits"][name] = int(count)
        elif line.startswith("DA:"):
            line_number, count = line[3:].split(",", 1)
            current["lines"][int(line_number)] = int(count)
    return records


def parse_inventory(path):
    return [
        json.loads(line)
        for line in Path(path).read_text(encoding="utf-8").splitlines()
        if line
    ]


def source_record(records, suffix):
    matches = [value for key, value in records.items() if key.endswith(suffix)]
    if len(matches) != 1:
        raise ValueError(f"expected one LCOV source ending in {suffix!r}")
    return matches[0]


def function_lines(record, name):
    return [line for line, function in record["functions"] if function == name]


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def tool_version(command):
    result = subprocess.run(
        [command, "--version"],
        text=True,
        capture_output=True,
        check=True,
    )
    return result.stdout.splitlines()[0].strip()


def validate(lcov_path, inventory_path, elf_path, implementation=None):
    records = parse_lcov(lcov_path)
    inventory = parse_inventory(inventory_path)
    checks = {}

    entry = source_record(records, "arch/x86/x86_64/entry.S")
    svm_entry = source_record(records, "arch/x86/hvm/svm/entry.S")
    memset = source_record(records, "arch/x86/memset.S")
    mmconfig = source_record(records, "arch/x86/x86_64/mmconfig_64.c")
    head = source_record(records, "arch/x86/boot/head.S")
    gen_idt = source_record(records, "arch/x86/include/asm/gen-idt.h")

    checks["svm_byte_fix"] = all(svm_entry["lines"].get(line, 0) > 0
                                   for line in (87, 89, 90))
    checks["no_memset_l3t_unlock"] = not function_lines(memset, "l3t_unlock")
    checks["no_mmconfig_ret_from_intr"] = not function_lines(
        mmconfig, "ret_from_intr"
    )
    checks["entry_779_not_hit"] = entry["lines"].get(779) == 0
    checks["handle_exception_location"] = bool(
        function_lines(entry, "handle_exception")
    ) and 779 not in function_lines(entry, "handle_exception")
    checks["trap_nop_not_misattributed"] = 1234 not in function_lines(
        entry, "trap_nop"
    )
    checks["common_interrupt_present"] = bool(
        function_lines(entry, "common_interrupt")
    )
    checks["handle_ist_exception_present"] = bool(
        function_lines(entry, "handle_ist_exception")
    )
    checks["head_has_executed_lines"] = any(head["lines"].values())
    checks["entry_function_total"] = len(entry["functions"]) == 26
    checks["generated_idt_function_total"] = len(gen_idt["functions"]) == 42
    checks["unique_function_names_per_source"] = all(
        len(record["functions"])
        == len({name for _, name in record["functions"]})
        for record in records.values()
    )

    inventory_by_name = {record["name"]: record for record in inventory}
    expected_unmapped_hits = {
        "entry_0xf1": 5756,
        "entry_0xfa": 119312,
        "entry_0xfb": 195,
        "entry_0xfc": 1,
        "entry_0xfd": 3,
        "__x86_indirect_thunk_rcx": 2,
        "__x86_indirect_thunk_rdx": 395,
        "__x86_indirect_thunk_rbx": 17553,
        "__x86_indirect_thunk_rbp": 128447,
        "__x86_indirect_thunk_r9": 303,
        "__x86_indirect_thunk_r12": 1,
        "__x86_indirect_thunk_r13": 4,
        "__x86_indirect_thunk_r14": 1,
    }
    for name, expected_hits in expected_unmapped_hits.items():
        checks[f"inventory_{name}"] = (
            name in inventory_by_name
            and inventory_by_name[name]["status"] == "omitted-no-source"
            and inventory_by_name[name]["hits"] == expected_hits
        )

    assembly_records = {
        name: record
        for name, record in records.items()
        if name.endswith(".S") or name.endswith("/asm/gen-idt.h")
    }
    status_counts = Counter(record["status"] for record in inventory)
    assembly_lines = sum(
        len(record["lines"]) for record in assembly_records.values()
    )
    assembly_hit_lines = sum(
        sum(count > 0 for count in record["lines"].values())
        for record in assembly_records.values()
    )
    assembly_functions = sum(
        len(record["functions"]) for record in assembly_records.values()
    )
    assembly_hit_functions = sum(
        sum(count > 0 for count in record["function_hits"].values())
        for record in assembly_records.values()
    )
    checks["assembly_totals"] = (
        len(assembly_records),
        assembly_hit_lines,
        assembly_lines,
        assembly_hit_functions,
        assembly_functions,
    ) == (13, 275, 815, 16, 78)
    checks["inventory_total"] = sum(status_counts.values()) == 3041

    summary = {
        "schema": "qemu-etrace-xen-assembly-validation-v1",
        "qemu_etrace_revision": implementation,
        "elf_sha256": sha256(elf_path),
        "lcov_sha256": sha256(lcov_path),
        "inventory_sha256": sha256(inventory_path),
        "assembly_source_files": len(assembly_records),
        "assembly_lines": assembly_lines,
        "assembly_hit_lines": assembly_hit_lines,
        "assembly_functions": assembly_functions,
        "assembly_hit_functions": assembly_hit_functions,
        "inventory_statuses": dict(sorted(status_counts.items())),
        "tools": {
            "dwarfdump": tool_version("dwarfdump"),
            "nm": tool_version("nm"),
        },
        "checks": checks,
    }
    return summary


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--lcov", required=True)
    parser.add_argument("--inventory", required=True)
    parser.add_argument("--elf", required=True)
    parser.add_argument("--output")
    parser.add_argument("--implementation")
    parser.add_argument("--expected")
    args = parser.parse_args()

    summary = validate(
        args.lcov,
        args.inventory,
        args.elf,
        implementation=args.implementation,
    )
    output = json.dumps(summary, indent=2, sort_keys=True) + "\n"
    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
    else:
        print(output, end="")

    if summary["elf_sha256"] != EXPECTED_ELF_SHA256:
        raise SystemExit("unexpected Xen ELF hash")
    failed = [name for name, passed in summary["checks"].items() if not passed]
    if failed:
        raise SystemExit("failed checks: " + ", ".join(failed))
    if args.expected:
        expected = json.loads(Path(args.expected).read_text(encoding="utf-8"))
        if summary != expected:
            raise SystemExit("validation summary does not match expected data")


if __name__ == "__main__":
    main()
