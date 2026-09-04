from pathlib import Path
import socket
import subprocess
import time

import pytest


ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / "qemu-etrace"


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
