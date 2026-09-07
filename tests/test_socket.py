from pathlib import Path
import socket
import subprocess
import time

import pytest

from tests.trace_builder import etrace_info, etrace_tb_def, etrace_tb_exec


ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / "qemu-etrace"
FIXTURE = ROOT / ".test-build" / "coverage-fixture"


def connect_unix(path, process):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            client.connect(str(path))
            return client
        except (FileNotFoundError, ConnectionRefusedError):
            client.close()
            if process.poll() is not None:
                stdout, stderr = process.communicate()
                raise AssertionError(
                    f"qemu-etrace exited early\nstdout:\n{stdout}\nstderr:\n{stderr}"
                )
            time.sleep(0.01)
    raise AssertionError("timed out connecting to qemu-etrace")


def test_server_closes_each_client_descriptor(tmp_path):
    proc_fds = Path("/proc/self/fd")
    if not proc_fds.is_dir():
        pytest.skip("file-descriptor accounting requires procfs")

    socket_path = tmp_path / "trace.sock"
    process = subprocess.Popen(
        [
            str(BINARY),
            "--trace",
            f"unix:{socket_path}",
            "--trace-in-format",
            "ascii-hex",
            "--trace-output",
            "none",
            "--server",
            "1",
        ],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    fd_counts = []
    try:
        for _ in range(6):
            client = connect_unix(socket_path, process)
            time.sleep(0.02)
            fd_counts.append(len(list(Path(f"/proc/{process.pid}/fd").iterdir())))
            client.sendall(b"1234\n")
            client.close()
    finally:
        process.terminate()
        try:
            process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate()

    assert max(fd_counts) - min(fd_counts) <= 1


def test_online_ordered_replay(tmp_path):
    symbols = subprocess.run(
        ["nm", "-S", str(FIXTURE)],
        text=True,
        capture_output=True,
        check=True,
    ).stdout.splitlines()
    address = next(
        int(fields[0], 16)
        for line in symbols
        if len(fields := line.split(maxsplit=3)) == 4
        and fields[3] == "covered"
    )
    socket_path = tmp_path / "ordered.sock"
    output = tmp_path / "ordered.txt"
    process = subprocess.Popen(
        [
            str(BINARY),
            "--trace",
            f"unix:{socket_path}",
            "--trace-output",
            str(output),
            "--elf",
            str(FIXTURE),
            "--auto-map",
            "--preserve-order",
            "--server",
            "0",
        ],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    client = connect_unix(socket_path, process)
    client.sendall(
        etrace_info(major=1)
        + etrace_tb_def(tb_id=1, vaddr=address, insns=((0, 4),))
        + etrace_tb_exec(tb_id=1, sequence=1, insn_count=1)
    )
    client.close()
    stdout, stderr = process.communicate(timeout=10)

    assert process.returncode == 0, f"stdout:\n{stdout}\nstderr:\n{stderr}"
    assert any(
        line.startswith(f"E0 {address:x} ")
        for line in output.read_text(encoding="ascii").splitlines()
    )
