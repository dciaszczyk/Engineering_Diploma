"""Stawia w sieci LAN wszystko, czego potrzebuje szkic examples/Benchmark na ESP32:
katalog, 6 relayów onion (rejestrują się same), cele (jawny i e2e) oraz serwery porównawcze
(HTTP, HTTPS, MQTT, MQTTS, CoAP) z licznikami bajtów.

  python serve_lan.py --ip 192.168.1.10      # adres tego komputera widoczny dla ESP32
  python3 serve_lan.py --ip 192.168.1.10     # to samo na Linuksie

Wypisuje adresy i klucz celu e2e do wpisania w szkicu. Ctrl+C kończy wszystkie procesy.
"""
import argparse
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
PY = HERE.parent / "python"
if not PY.is_dir():
    sys.exit(f"Brak katalogu {PY} (oczekiwany obok '{HERE.name}') z modułem onion_common.py")
sys.path.insert(0, str(PY))
from onion_common import X25519PrivateKey, priv_bytes, pub_bytes   # noqa: E402


def find_openssl() -> str | None:
    """Znajduje openssl.exe: najpierw w PATH, potem w typowych lokalizacjach Windows."""
    exe = shutil.which("openssl")
    if exe:
        return exe

    candidates = [
        Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "OpenSSL-Win64" / "bin" / "openssl.exe",
        Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "OpenSSL-Win32" / "bin" / "openssl.exe",
        Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Git" / "usr" / "bin" / "openssl.exe",
        Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")) / "Git" / "usr" / "bin" / "openssl.exe",
        Path(r"C:\OpenSSL-Win64\bin\openssl.exe"),
        Path(r"C:\OpenSSL-Win32\bin\openssl.exe"),
    ]
    for cand in candidates:
        if cand.is_file():
            return str(cand)
    return None


ap = argparse.ArgumentParser()
ap.add_argument("--ip", required=True, help="adres IP tego komputera w LAN")
args = ap.parse_args()

# --- katalog roboczy zależny od systemu (Windows: %TEMP%\onion_lan, Linux: /tmp/onion_lan) ---
work = Path(tempfile.gettempdir()) / "onion_lan"
work.mkdir(parents=True, exist_ok=True)

cert_path = work / "cert.pem"
key_path = work / "key.pem"

# --- generacja self-signed certu (z uwzględnieniem MSYS path-conv) ---
if not (cert_path.exists() and key_path.exists()):
    openssl_exe = find_openssl()
    if not openssl_exe:
        sys.exit(
            "Nie znaleziono 'openssl'. Zainstaluj OpenSSL (np. 'winget install ShiningLight.OpenSSL.Light') "
            "lub dodaj katalog z openssl.exe do PATH.\n"
            "Typowe ścieżki: C:\\Program Files\\OpenSSL-Win64\\bin  lub  C:\\Program Files\\Git\\usr\\bin"
        )
    env_ssl = dict(os.environ, MSYS_NO_PATHCONV="1", MSYS2_ARG_CONV_EXCL="*")
    r = subprocess.run(
        [openssl_exe, "req", "-x509", "-newkey", "ec",
         "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
         "-keyout", str(key_path),
         "-out", str(cert_path),
         "-days", "30", "-subj", "/CN=onion-lan"],
        env=env_ssl, capture_output=True, text=True,
    )
    if r.returncode != 0:
        sys.exit("openssl nie wygenerował certyfikatu:\n" + (r.stderr or r.stdout or ""))

env = dict(
    os.environ,
    PYTHONPATH=str(PY),
    PUBLIC_IP=args.ip,
    DIRECTORY_URL="http://127.0.0.1:8080",
    CERT=str(cert_path),
    KEY=str(key_path),
)
procs = []


def spawn(cmd, **extra):
    procs.append(subprocess.Popen(cmd, env=dict(env, **extra), cwd=str(PY)))


spawn([sys.executable, "-u", "directory.py", "--port", "8080", "--ttl", "120"])
time.sleep(1)

for i in range(1, 7):
    k = X25519PrivateKey.generate()
    spawn([sys.executable, "-u", "relay.py"],
          PORT=str(8000 + i),
          RELAY_NAME=f"lan{i}",
          RELAY_STATIC_KEY=priv_bytes(k).hex())

spawn([sys.executable, "-u", "dest_server.py"], PORT="9000")

dk = X25519PrivateKey.generate()
spawn([sys.executable, "-u", "dest_server.py"],
      PORT="9001",
      DEST_KEY=priv_bytes(dk).hex(),
      DEST_NAME="secure")

procs.append(subprocess.Popen(
    [sys.executable, "-u", str(HERE / "bench_servers.py"), str(cert_path), str(key_path)],
    env=dict(env, BENCH_BIND="0.0.0.0"),
))

print(f"""
Katalog:          http://{args.ip}:8080        (relaye lan1..lan6 rejestrują się same)
Cel jawny:        {args.ip}:9000      Cel e2e: {args.ip}:9001 (nazwa "secure" w katalogu)
Serwery porównawcze (porty proxy): HTTP 19601, HTTPS 19602, MQTT 19603, MQTTS 19604, CoAP/UDP 19605
Katalog roboczy:  {work}
W szkicu Benchmark ustaw HOST = "{args.ip}". Ctrl+C kończy.""", flush=True)

try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    print("\nZatrzymuję procesy…", flush=True)
finally:
    for p in procs:
        try:
            p.terminate()
        except Exception:
            pass
    for p in procs:
        try:
            p.wait(timeout=3)
        except Exception:
            try:
                p.kill()
            except Exception:
                pass