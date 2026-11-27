"""Install a CPU-only Ollama service or reuse the local endpoint, then prepare a model."""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, build_opener, ProxyHandler, urlopen

VERSION = "0.20.0"
ARCH = {
    "x86_64": ("amd64", "60865e897ebd0f1fd481df2428fbbaf708e776b7926a3a24a1bb5bd0dd83d546"),
    "aarch64": ("arm64", "7d08fe253b98e9e9b722b390e3e3660337f2522158fc13977fba42978fa7be35"),
}
UNIT = "vpnguard-ollama.service"
ROOT = Path("/opt/vpnguard-ollama")
API = "http://127.0.0.1:11434/api/"
LOCAL = build_opener(ProxyHandler({}))


def call(path, body=None, timeout=10):
    data = json.dumps(body).encode() if body is not None else None
    return LOCAL.open(Request(API + path, data=data, headers={"Content-Type": "application/json"}), timeout=timeout)


def ready():
    try:
        with call("version", timeout=2) as response:
            return bool(json.loads(response.read(8192)).get("version"))
    except (ValueError, OSError):
        return False


def command(*args, timeout=180):
    subprocess.run(args, check=True, stdout=subprocess.DEVNULL, timeout=timeout)


def install_engine(progress):
    architecture = ARCH.get(platform.machine())
    if architecture is None:
        raise ValueError("Установка поддерживает Linux amd64 и arm64")
    arch, expected = architecture
    ROOT.mkdir(parents=True, exist_ok=True)
    ROOT.chmod(0o755)
    target = ROOT / VERSION
    if not target.exists():
        if not shutil.which("zstd"):
            progress("Установка zstd из APT")
            command("apt-get", "update", timeout=300)
            command("apt-get", "install", "-y", "--no-install-recommends", "zstd", timeout=300)
        with tempfile.TemporaryDirectory(dir=ROOT) as tmp:
            staging = Path(tmp)
            archive = staging / "archive.zst"
            url = f"https://github.com/ollama/ollama/releases/download/v{VERSION}/ollama-linux-{arch}.tar.zst"
            progress("Загрузка архива Ollama")
            digest, total, reported = hashlib.sha256(), 0, -1
            with urlopen(url, timeout=60) as src, archive.open("wb") as dest:
                while chunk := src.read(1 << 20):
                    dest.write(chunk)
                    digest.update(chunk)
                    total += len(chunk)
                    if total // (64 << 20) != reported:
                        reported = total // (64 << 20)
                        progress(f"Загрузка Ollama: {total >> 20} МиБ")
            if digest.hexdigest() != expected:
                raise ValueError("Контрольная сумма архива Ollama не совпала")
            engine = staging / "runtime"
            engine.mkdir()
            progress("Распаковка CPU-компонентов Ollama")
            command("tar", "--zstd", "-xf", str(archive), "-C", str(engine), "--no-same-owner", "--same-permissions",
                    "--wildcards", "--no-wildcards-match-slash", "bin/ollama", "lib/ollama/*.so*", timeout=300)
            for directory in (engine, engine / "bin", engine / "lib", engine / "lib/ollama"):
                directory.chmod(0o755)
            engine.rename(target)
    unit = f"""[Unit]
Description=VpnGuard local Ollama
After=network.target

[Service]
ExecStart={target}/bin/ollama serve
DynamicUser=yes
StateDirectory=vpnguard-ollama
Environment=HOME=/var/lib/vpnguard-ollama
Environment=OLLAMA_MODELS=/var/lib/vpnguard-ollama/models
Environment=OLLAMA_HOST=127.0.0.1:11434
Environment=OLLAMA_NO_CLOUD=1
Environment=OLLAMA_NUM_PARALLEL=1
Restart=on-failure
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
"""
    directory = Path("/etc/systemd/system")
    with tempfile.NamedTemporaryFile(mode="w", dir=directory, delete=False) as f:
        f.write(unit)
        name = f.name
    os.chmod(name, 0o644)
    os.replace(name, directory / UNIT)
    command("systemctl", "daemon-reload")
    command("systemctl", "enable", "--now", UNIT)


def prepare(model, progress):
    if not ready():
        unit = subprocess.run(["systemctl", "show", "ollama.service", "-p", "LoadState", "--value"],
                              capture_output=True, text=True, timeout=10)
        if unit.stdout.strip() == "loaded":
            progress("Запуск установленной службы Ollama")
            command("systemctl", "start", "ollama.service")
        elif unit.stdout.strip() == "not-found":
            install_engine(progress)
        else:
            raise ValueError("Не удалось определить состояние службы ollama.service")
        for _ in range(30):
            if ready():
                break
            time.sleep(1)
        else:
            raise ValueError("Служба Ollama не ответила на локальном порту 11434")
    def check():
        with call("show", {"model": model}) as response:
            data = json.loads(response.read(2 << 20))
            if (not isinstance(data, dict) or not isinstance(data.get("details"), dict)
                    or "error" in data or data.get("remote_host") or data.get("remote_model")):
                raise ValueError("Требуется локальная модель Ollama")
    try:
        check()
        return
    except HTTPError as exc:
        if exc.code != 404:
            raise
    progress("Загрузка модели " + model)
    with call("pull", {"model": model, "stream": True}, timeout=180) as response:
        while line := response.readline(65537):
            if len(line) > 65536:
                raise ValueError("Слишком большой ответ Ollama")
            row = json.loads(line)
            if row.get("error"):
                raise ValueError("Ошибка загрузки модели: " + str(row["error"])[:200])
            if row.get("status") == "success":
                break
            total, done = row.get("total"), row.get("completed")
            if isinstance(total, int) and total > 0 and isinstance(done, int):
                progress(f"Загрузка {model}: {min(100, 100 * done // total)}% текущего файла")
        else:
            raise ValueError("Загрузка модели прервана")
    check()


if __name__ == "__main__":
    try:
        with open("/run/vpnguard-ollama-setup.lock", "a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            prepare(sys.argv[1], lambda text: print(text, flush=True))
    except (OSError, URLError, ValueError, subprocess.SubprocessError) as exc:
        sys.exit(str(exc))
