from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[1]


def test_wrapper_preserves_tool_and_user_arguments(tmp_path):
    target = tmp_path / "fake-etrace"
    target.write_text("#!/bin/sh\nprintf '<%s>\\n' \"$@\"\n", encoding="ascii")
    target.chmod(0o755)
    install = tmp_path / "binutils"
    (install / "bin").mkdir(parents=True)
    wrapper = Path(f"{target}.sh")

    subprocess.run(
        [
            "make",
            "-f",
            str(ROOT / "Makefile"),
            str(wrapper),
            f"TARGET={target}",
            f"BU_INSTALLDIR={install}",
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=True,
    )
    result = subprocess.run(
        [str(wrapper), "argument with spaces", "*.trace"],
        text=True,
        capture_output=True,
        check=True,
    )

    assert result.stdout.splitlines() == [
        "<--nm>",
        f"<{install}/bin/nm>",
        "<--objdump>",
        f"<{install}/bin/objdump>",
        "<--addr2line>",
        f"<{install}/bin/addr2line>",
        "<argument with spaces>",
        "<*.trace>",
    ]
