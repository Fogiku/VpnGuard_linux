"""Generate an ordinary console/SSH/web password and a Linux-compatible hash."""
import secrets,shutil,string,subprocess
from pathlib import Path

def create():
    alphabet="abcdefghjkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ23456789"
    password="Vpn-"+"".join(secrets.choice(alphabet) for _ in range(12))+"!"
    candidates=[shutil.which("openssl"),"C:/Espressif/tools/git/usr/bin/openssl.exe","C:/Program Files/Git/usr/bin/openssl.exe"]
    openssl=next((p for p in candidates if p and Path(p).is_file()),None)
    if not openssl:raise ValueError("OpenSSL is required to prepare a normal console password")
    result=subprocess.run([openssl,"passwd","-6","-stdin"],input=(password+"\n").encode("utf-8"),capture_output=True,check=True)
    hashed=result.stdout.decode("ascii").strip()
    if not hashed.startswith("$6$"):raise ValueError("Unexpected password hash")
    return password,hashed
