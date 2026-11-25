"""Miniserwer katalogu relayów i usług (PROTOTYP: ufamy każdemu wpisowi, bez uwierzytelniania).

  python3 directory.py [--port 8080] [--ttl 300]

  POST /register   {"name","port","pub","ver","kind":"relay"|"service"[,"ip"]}
                   relay/cel wrzuca swój wpis po starcie i odświeża go co minutę;
                   gdy brak "ip", serwer bierze adres z połączenia
  GET  /nodes?kind=relay&ver=3   lista wpisów [{"name","ip","port","pub"}]
                   (kind i ver są opcjonalnymi filtrami; wpisy bez odświeżenia przez --ttl s znikają)
"""
import argparse
import json
import re
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

nodes = {}              # (kind, ip, port) -> wpis
lock = threading.Lock()
ttl = 300


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        print("[directory]", self.address_string(), fmt % args, flush=True)

    def _reply(self, code, body):
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        if urlparse(self.path).path != "/register":
            return self._reply(404, {"error": "not found"})
        try:
            body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))
            entry = {"name": str(body.get("name", "node")), "ip": str(body.get("ip") or self.client_address[0]),
                     "port": int(body["port"]), "pub": str(body["pub"]).lower(),
                     "ver": int(body.get("ver", 0)), "kind": str(body.get("kind", "relay"))}
            if not re.fullmatch(r"[0-9a-f]{64}", entry["pub"]) or not 0 < entry["port"] < 65536:
                raise ValueError("bad pub or port")
        except (KeyError, ValueError, json.JSONDecodeError) as e:
            return self._reply(400, {"error": str(e)})
        with lock:
            nodes[(entry["kind"], entry["ip"], entry["port"])] = dict(entry, seen=time.time())
        self._reply(200, {"ok": True, "ip": entry["ip"]})

    def do_GET(self):
        url = urlparse(self.path)
        if url.path != "/nodes":
            return self._reply(200, {"service": "onion directory"})
        q = parse_qs(url.query)
        kind, ver = q.get("kind", [None])[0], q.get("ver", [None])[0]
        now = time.time()
        with lock:
            for k in [k for k, v in nodes.items() if now - v["seen"] > ttl]:
                del nodes[k]
            out = [{f: v[f] for f in ("name", "ip", "port", "pub")}     # lekka odpowiedź: mieści się w małym buforze JSON na ESP32
                   for v in nodes.values()
                   if (kind is None or v["kind"] == kind) and (ver is None or v["ver"] == int(ver))]
        self._reply(200, sorted(out, key=lambda n: (n["name"], n["port"])))


def main():
    global ttl
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--ttl", type=int, default=300)
    args = ap.parse_args()
    ttl = args.ttl
    print(f"[directory] listening on :{args.port} (ttl {ttl}s)", flush=True)
    ThreadingHTTPServer(("0.0.0.0", args.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
