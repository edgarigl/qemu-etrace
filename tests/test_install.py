import os
from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[1]


def test_install_places_plugin_under_libdir(tmp_path):
    api7_header = tmp_path / "qemu-plugin.h"
    api7_header.write_text(
        "#define QEMU_PLUGIN_VERSION 7\n"
        f'#include "{ROOT}/tests/plugin/qemu-plugin.h"\n',
        encoding="ascii",
    )

    common_args = [
        "make",
        "install",
        "prefix=/usr",
        f"DESTDIR={tmp_path}/root",
    ]
    subprocess.run(
        common_args
        + [
            f"PLUGIN={tmp_path}/libqemu-etrace-v5.so",
            f"QEMU_PLUGIN_HEADER={ROOT}/tests/plugin/qemu-plugin.h",
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=True,
    )
    subprocess.run(
        common_args
        + [
            f"PLUGIN={tmp_path}/libqemu-etrace-v7.so",
            f"QEMU_PLUGIN_HEADER={api7_header}",
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=True,
    )

    assert (tmp_path / "root/usr/bin/qemu-etrace").is_file()
    viewer = tmp_path / "root/usr/bin/etrace-view"
    viewer_data = tmp_path / "root/usr/share/qemu-etrace"
    assert viewer.is_file()
    assert "/usr/share/qemu-etrace" in viewer.read_text(encoding="utf-8")
    assert (viewer_data / "etrace-view.py").is_file()
    assert (viewer_data / "etrace.py").is_file()
    assert (viewer_data / "addr2line.py").is_file()
    assert (
        tmp_path / "root/usr/lib/qemu-etrace/plugins/5/libqemu-etrace.so"
    ).is_file()
    assert (
        tmp_path / "root/usr/lib/qemu-etrace/plugins/7/libqemu-etrace.so"
    ).is_file()

    env = os.environ.copy()
    env["QEMU_ETRACE_DATADIR"] = str(viewer_data)
    result = subprocess.run(
        [viewer, "--help"],
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0
    assert "--trace" in result.stdout
