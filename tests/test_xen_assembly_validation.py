import json
from pathlib import Path

from tests.xen_assembly_validation import parse_inventory, parse_lcov


ROOT = Path(__file__).resolve().parents[1]


def test_parse_lcov_preserves_function_locations_and_hits(tmp_path):
    path = tmp_path / "coverage.info"
    path.write_text(
        "TN:\n"
        "SF:/src/example.S\n"
        "FN:10,first\n"
        "FN:20,second\n"
        "FNDA:3,first\n"
        "FNDA:0,second\n"
        "DA:10,3\n"
        "DA:20,0\n"
        "LF:2\n"
        "LH:1\n"
        "end_of_record\n",
        encoding="utf-8",
    )

    record = parse_lcov(path)["/src/example.S"]

    assert record["functions"] == [(10, "first"), (20, "second")]
    assert record["function_hits"] == {"first": 3, "second": 0}
    assert record["lines"] == {10: 3, 20: 0}


def test_parse_inventory_reads_json_lines(tmp_path):
    path = tmp_path / "inventory.jsonl"
    objects = [
        {"name": "first", "status": "emitted"},
        {"name": "second", "status": "omitted-no-source"},
    ]
    path.write_text(
        "".join(json.dumps(obj) + "\n" for obj in objects),
        encoding="utf-8",
    )

    assert parse_inventory(path) == objects


def test_checked_xen_summary_passes_all_checks():
    path = ROOT / "tests" / "fixtures" / "xen-assembly-validation.json"
    summary = json.loads(path.read_text(encoding="utf-8"))

    assert summary["elf_sha256"] == (
        "e1e8dcb0f74ca20b380294c28abeda01da82e1e0d9713ea6488132b3c9149a64"
    )
    assert summary["assembly_source_files"] == 13
    assert summary["assembly_hit_lines"] == 275
    assert summary["assembly_lines"] == 815
    assert summary["assembly_hit_functions"] == 16
    assert summary["assembly_functions"] == 78
    assert all(summary["checks"].values())
