"""Run one agent-selected built-in profile in a disposable Linux namespace."""
import http.client
import http.server
import os
import secrets
from pathlib import Path
import socket
import subprocess
import sys
import time


class ProbeHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = self.path.encode("ascii")
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def exchange(queued):
    with http.server.HTTPServer(("127.0.0.1", 0), ProbeHandler) as server:
        port = server.server_port
        if queued:
            # Only this local client-to-server connection enters the isolated queue.
            script = ("table ip vg_trial {\n chain out { type filter hook output priority filter; policy accept;\n"
                      f' oifname "lo" ip daddr 127.0.0.1 tcp dport {port} queue num 200\n }}\n}}\n')
            subprocess.run(["nft", "-f", "-"], input=script, text=True, check=True, timeout=2)
        path = "/" + secrets.token_hex(16)
        client = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
        try:
            client.request("GET", path)
            server.timeout = 2
            server.handle_request()
            with client.getresponse() as reply:
                if reply.status != 200 or reply.read(128) != path.encode("ascii"):
                    raise ValueError("неверный ответ испытательного HTTP-сервера")
        finally:
            client.close()


def queue_state(queue, pid):
    try:
        rows = queue.read_text().splitlines()
    except FileNotFoundError:
        return None
    for row in rows:
        fields = row.split()
        if len(fields) >= 8 and fields[:2] == ["200", str(pid)]:
            # kernel drops, userspace delivery drops and packet ID sequence
            return tuple(int(field) for field in fields[5:8])
    return None


def verify(parent, mode, args):
    if mode not in ("startup", "http"):
        raise ValueError("неизвестный режим испытания")
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
                if queue_state(queue, proc.pid) is not None:
                    if mode == "startup":
                        return "ready"
                    subprocess.run(["ip", "link", "set", "lo", "up"], check=True, timeout=2)
                    exchange(False)
                    before = queue_state(queue, proc.pid)
                    exchange(True)
                    after = queue_state(queue, proc.pid)
                    if (not before or not after or proc.poll() is not None or
                            after[:2] != before[:2] or after[2] <= before[2]):
                        raise ValueError("не подтверждено прохождение пакетов через очередь профиля")
                    return f"http {after[2] - before[2]}"
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
        print(verify(sys.argv[1], sys.argv[2], sys.argv[3:]))
    except (OSError, ValueError, subprocess.SubprocessError, http.client.HTTPException) as exc:
        sys.exit(str(exc))
