"""Run one agent-selected built-in profile in a disposable Linux namespace."""
import os
from pathlib import Path
import socket
import subprocess
import sys
import time


def verify(parent, args):
    if (os.getpid() != 1 or os.readlink("/proc/self/ns/net") == parent
            or [name for _, name in socket.if_nameindex()] != ["lo"]):
        raise ValueError("требуется отдельное пространство PID и сети")
    root = Path("/opt/zapret2")
    binary = root / "nfq2/nfqws2"
    if not os.access(binary, os.X_OK):
        raise ValueError("не найден исполняемый /opt/zapret2/nfq2/nfqws2")
    queue = Path("/proc/net/netfilter/nfnetlink_queue")
    with subprocess.Popen([binary, *args], cwd=root, stdin=subprocess.DEVNULL,
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) as proc:
        try:
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                if proc.poll() is not None:
                    raise ValueError(f"процесс завершился до готовности (код {proc.returncode}); проверьте версию и файлы Lua")
                try:
                    rows = [line.split() for line in queue.read_text().splitlines()]
                except FileNotFoundError:
                    rows = []
                if any(row[:2] == ["200", str(proc.pid)] for row in rows):
                    return
                time.sleep(.05)
            raise ValueError("процесс не подтвердил владение NFQUEUE 200")
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=1)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()


if __name__ == "__main__":
    try:
        verify(sys.argv[1], sys.argv[2:])
    except (OSError, ValueError) as exc:
        sys.exit(str(exc))
    print("ready")
