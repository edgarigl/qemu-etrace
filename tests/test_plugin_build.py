from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[1]
FEATURE_DEFINE = "-DHAVE_QEMU_PLUGIN_VCPU_DISCON_CB"


def plugin_build_command(tmp_path, declaration):
    include_dir = tmp_path / "include"
    include_dir.mkdir()
    header = include_dir / "qemu-plugin.h"
    header.write_text(
        "#define QEMU_PLUGIN_VERSION 5\n" + declaration,
        encoding="ascii",
    )
    plugin = tmp_path / "libqemu-etrace.so"
    result = subprocess.run(
        [
            "make",
            "-sn",
            "plugin",
            f"QEMU_PLUGIN_HEADER={header}",
            f"PLUGIN={plugin}",
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    return result.stdout


def test_plugin_build_omits_discontinuity_feature_for_old_header(tmp_path):
    command = plugin_build_command(tmp_path, "")

    assert FEATURE_DEFINE not in command


def test_plugin_build_enables_discontinuity_feature_from_declaration(tmp_path):
    command = plugin_build_command(
        tmp_path,
        "void qemu_plugin_register_vcpu_discon_cb(void);\n",
    )

    assert FEATURE_DEFINE in command
