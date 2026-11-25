"""Stawia w sieci LAN wszystko, czego potrzebuje szkic examples/Benchmark na ESP32:
katalog, 6 relayów onion (rejestrują się same), cele (jawny i e2e) oraz serwery porównawcze
(HTTP, HTTPS, MQTT, MQTTS, CoAP) z licznikami bajtów.

  python3 serve_lan.py --ip 192.168.1.10        # adres tego komputera widoczny dla ESP32

Wypisuje adresy i klucz celu e2e do wpisania w szkicu. Ctrl+C kończy wszystkie procesy."""
import argparse
import os
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
PY = HERE.parent / "python"
sys.path.insert(0, str(PY))
from onion_common import X25519PrivateKey, priv_bytes, pub_bytes   # noqa: E402

ap = argparse.ArgumentParser()
ap.add_argument("--ip", required=True, help="adres IP tego komputera w LAN")
args = ap.parse_args()

work = Path("/tmp/onion_lan")
work.mkdir(exist_ok=True)
if not (work / "cert.pem").exists():
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
                    "-keyout", str(work / "key.pem"), "-out", str(work / "cert.pem"), "-days", "30", "-subj", "/CN=onion-lan"],
                   check=True, capture_output=True)
env = dict(os.environ, PYTHONPATH=str(PY), PUBLIC_IP=args.ip, DIRECTORY_URL="http://127.0.0.1:8080",
           CERT=str(work / "cert.pem"), KEY=str(work / "key.pem"))
procs = []


def spawn(cmd, **extra):
    procs.append(subprocess.Popen(cmd, env=dict(env, **extra), cwd=PY))


spawn([sys.executable, "-u", "directory.py", "--port", "8080", "--ttl", "120"])
time.sleep(1)
for i in range(1, 7):
    k = X25519PrivateKey.generate()
    spawn([sys.executable, "-u", "relay.py"], PORT=str(8000 + i), RELAY_NAME=f"lan{i}", RELAY_STATIC_KEY=priv_bytes(k).hex())
spawn([sys.executable, "-u", "dest_server.py"], PORT="9000")
dk = X25519PrivateKey.generate()
spawn([sys.executable, "-u", "dest_server.py"], PORT="9001", DEST_KEY=priv_bytes(dk).hex(), DEST_NAME="secure")
procs.append(subprocess.Popen([sys.executable, "-u", str(HERE / "bench_servers.py"), str(work / "cert.pem"), str(work / "key.pem")],
                              env=dict(env, BENCH_BIND="0.0.0.0")))
print(f"""
Katalog:          http://{args.ip}:8080        (relaye lan1..lan6 rejestrują się same)
Cel jawny:        {args.ip}:9000      Cel e2e: {args.ip}:9001 (nazwa "secure" w katalogu)
Serwery porównawcze (porty proxy): HTTP 19601, HTTPS 19602, MQTT 19603, MQTTS 19604, CoAP/UDP 19605
W szkicu Benchmark ustaw HOST = "{args.ip}". Ctrl+C kończy.""", flush=True)
try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    pass
finally:
    for p in procs:
        p.terminate()
