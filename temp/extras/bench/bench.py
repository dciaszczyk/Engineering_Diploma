"""Porównanie onion (client.py) z HTTP, HTTPS, MQTT i CoAP: opóźnienie, bajty na łączu klienta,
liczba połączeń, CPU klienta, liczba operacji kryptograficznych.

  python3 bench.py [--n 30] [--payload 64] [--quick]

Uczciwość pomiaru: klienty są minimalnymi implementacjami w Pythonie (ta sama sieć loopback, ten sam
interpreter), serwery i relaye działają w osobnych procesach, a bajty liczy proxy na łączu klienta.
To porównanie KOSZTU PROTOKOŁÓW (bajty, połączenia, handshake'e, operacje krypto), a nie
wydajności ESP32: bezwzględne czasy i zużycie pamięci zmierz na urządzeniu (examples/Benchmark).
"""
import argparse
import asyncio
import json
import multiprocessing as mp
import os
import socket
import ssl
import statistics
import struct
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "hosttest"))
sys.path.insert(0, str(HERE.parent / "python"))
sys.path.insert(0, str(HERE))
from common import PY, RUN, ensure_certs, spawn, stop_all, wait_port   # noqa: E402
import bench_servers                                                    # noqa: E402
import client as onion_client                                           # noqa: E402
import onion_common                                                     # noqa: E402
from onion_common import X25519PrivateKey, priv_bytes, pub_bytes        # noqa: E402

OPS = {"x25519": 0, "aead": 0}      # liczniki operacji krypto po stronie klienta onion


# ---------- klienty protokołów (minimalne, ale poprawne) ----------
def tls_ctx():
    c = ssl.create_default_context()
    c.check_hostname = False
    c.verify_mode = ssl.CERT_NONE
    return c


class Http:
    """HTTP/1.1 POST. keepalive=False: nowe połączenie na wiadomość (Connection: close)."""
    def __init__(self, port, tls, keepalive):
        self.port, self.tls, self.keep, self.rw = port, tls, keepalive, None

    async def _open(self):
        return await asyncio.open_connection("127.0.0.1", self.port, ssl=tls_ctx() if self.tls else None)

    async def send(self, payload):
        r, w = self.rw if (self.keep and self.rw) else await self._open()
        w.write(b"POST /data HTTP/1.1\r\nHost: sensor\r\nContent-Type: application/octet-stream\r\nContent-Length: " +
                str(len(payload)).encode() + (b"\r\nConnection: keep-alive" if self.keep else b"\r\nConnection: close") +
                b"\r\n\r\n" + payload)
        await w.drain()
        head = await r.readuntil(b"\r\n\r\n")
        n = int(head.lower().split(b"content-length:")[1].split(b"\r\n")[0])
        await r.readexactly(n)
        if self.keep:
            self.rw = (r, w)
        else:
            w.close()

    async def close(self):
        if self.rw:
            self.rw[1].close()
        self.rw = None


def _varint(n):
    out = b""
    while True:
        d, n = n % 128, n // 128
        out += bytes([d | (128 if n else 0)])
        if not n:
            return out


class Mqtt:
    """MQTT 3.1.1, QoS 1. persistent=False: CONNECT, PUBLISH, DISCONNECT na każdą wiadomość."""
    def __init__(self, port, tls, persistent):
        self.port, self.tls, self.persistent, self.rw, self.pid = port, tls, persistent, None, 0

    async def _connect(self):
        r, w = await asyncio.open_connection("127.0.0.1", self.port, ssl=tls_ctx() if self.tls else None)
        var = b"\x00\x04MQTT\x04\x02\x00\x3c" + b"\x00\x06sensor"
        w.write(b"\x10" + _varint(len(var)) + var)
        await w.drain()
        await r.readexactly(4)                                    # CONNACK
        return r, w

    async def send(self, payload):
        r, w = self.rw if (self.persistent and self.rw) else await self._connect()
        self.pid = self.pid % 65535 + 1
        body = b"\x00\x04t/dt" + struct.pack(">H", self.pid) + payload
        w.write(b"\x32" + _varint(len(body)) + body)
        await w.drain()
        await r.readexactly(4)                                    # PUBACK
        if self.persistent:
            self.rw = (r, w)
        else:
            w.write(b"\xe0\x00")
            await w.drain()
            w.close()

    async def close(self):
        if self.rw:
            self.rw[1].write(b"\xe0\x00")
            self.rw[1].close()
        self.rw = None


class Coap:
    """CoAP CON POST /data po UDP, czeka na ACK 2.04."""
    def __init__(self, port):
        self.port, self.mid, self.transport, self.fut = port, 0, None, None

    async def send(self, payload):
        loop = asyncio.get_running_loop()
        if self.transport is None:
            outer = self

            class P(asyncio.DatagramProtocol):
                def datagram_received(self, data, addr):
                    if outer.fut and not outer.fut.done():
                        outer.fut.set_result(data)
            self.transport, _ = await loop.create_datagram_endpoint(P, remote_addr=("127.0.0.1", self.port))
        self.mid = (self.mid + 1) & 0xFFFF
        token = os.urandom(2)
        msg = bytes([0x40 | len(token), 0x02]) + struct.pack(">H", self.mid) + token + b"\xb4data" + b"\xff" + payload
        self.fut = loop.create_future()
        self.transport.sendto(msg)
        ack = await asyncio.wait_for(self.fut, 2)
        assert ack[1] == 0x44

    async def close(self):
        if self.transport:
            self.transport.close()
        self.transport = None


class Onion:
    """Obwód onion przez `hops` relayów. reuse=False: nowy obwód na wiadomość (jak w prototypie).
    e2e=True: szyfrowanie end-to-end do celu (dest_pub)."""
    def __init__(self, relays, dest_port, hops, reuse, dest_pub=None):
        self.relays, self.dest_port, self.hops, self.reuse, self.dest_pub = relays, dest_port, hops, reuse, dest_pub
        self.circuit = None

    async def send(self, payload):
        c = self.circuit
        if c is None:
            c = onion_client.OnionCircuit()
            await c.build(self.relays[:self.hops])
        status, _ = await c.send("127.0.0.1", self.dest_port, payload, self.dest_pub)
        assert status == "delivered", status
        if self.reuse:
            self.circuit = c
        else:
            await c.destroy()

    async def close(self):
        if self.circuit:
            await self.circuit.destroy()
        self.circuit = None


# ---------- pomiar ----------
def snapshot(ctr):
    return ctr[0], ctr[1], ctr[2]


async def measure(scen, ctr, n, payload, warmup=2):
    """Wysyła n wiadomości i zbiera metryki. Pierwsza wiadomość trwałych połączeń zawiera ich zestawienie."""
    for _ in range(warmup):                         # rozgrzewka (importy, cache), osobny obiekt nie jest potrzebny
        await scen.send(payload)
    await scen.close()                              # po rozgrzewce zaczynamy od czystego stanu (nowe połączenie/obwód)
    OPS["x25519"] = OPS["aead"] = 0

    lat, cpu, up, down, conns = [], [], [], [], []
    for _ in range(n):
        b0, t0, c0 = snapshot(ctr), time.perf_counter(), time.process_time()
        await scen.send(payload)
        lat.append((time.perf_counter() - t0) * 1000)
        cpu.append((time.process_time() - c0) * 1000)
        await asyncio.sleep(0.015)                  # pozwól proxy dolicz końcówki (close_notify itp.)
        b1 = snapshot(ctr)
        up.append(b1[0] - b0[0]); down.append(b1[1] - b0[1]); conns.append(b1[2] - b0[2])
    await scen.close()
    ops = dict(OPS)
    steady = lambda xs: statistics.median(xs[1:]) if len(xs) > 2 else statistics.median(xs)
    return {
        "n": n,
        "first_ms": lat[0], "median_ms": statistics.median(lat), "p95_ms": sorted(lat)[max(0, int(len(lat) * 0.95) - 1)],
        "bytes_up": sum(up) / n, "bytes_down": sum(down) / n, "bytes_total": (sum(up) + sum(down)) / n,
        "bytes_steady": steady([u + d for u, d in zip(up, down)]),
        "first_bytes": up[0] + down[0],
        "conns": sum(conns) / n, "cpu_ms": statistics.mean(cpu),
        "x25519": ops["x25519"] / n, "aead": ops["aead"] / n,
    }


def count_crypto():
    """Zlicza operacje krypto klienta onion (X25519, AES-GCM) bez zmiany ich działania."""
    def wrap(mod, name, key):
        orig = getattr(mod, name)

        def f(*a, **k):
            OPS[key] += 1
            return orig(*a, **k)
        setattr(mod, name, f)
    wrap(onion_client, "client_start", "x25519")
    wrap(onion_common, "dh", "x25519")
    wrap(onion_client, "encrypt_layer", "aead")
    wrap(onion_client, "decrypt_layer", "aead")
    wrap(onion_client, "e2e_seal_request", "x25519")        # jedno DH + generacja klucza
    wrap(onion_client, "e2e_open_response", "aead")


# ---------- główny program ----------
async def run(args):
    ensure_certs()
    # relaye onion (osobne procesy) i cele
    relays = []
    for i in range(1, 9):
        k = X25519PrivateKey.generate()
        relays.append({"ip": "127.0.0.1", "port": 18500 + i, "pub": pub_bytes(k).hex()})
        spawn(["python3", "-u", str(PY / "relay.py")], f"b_relay{i}.log", cwd=PY,
              env={"PORT": str(18500 + i), "RELAY_STATIC_KEY": priv_bytes(k).hex(),
                   "CERT": str(RUN / "cert.pem"), "KEY": str(RUN / "key.pem")})
    spawn(["python3", "-u", str(PY / "dest_server.py")], "b_dest.log", cwd=PY, env={"PORT": "19510"})
    dk = X25519PrivateKey.generate()
    spawn(["python3", "-u", str(PY / "dest_server.py")], "b_dest_e2e.log", cwd=PY,
          env={"PORT": "19511", "DEST_KEY": priv_bytes(dk).hex()})
    for p in [18501 + i for i in range(8)] + [19510, 19511]:
        wait_port(p)

    names = ("http", "https", "mqtt", "mqtts", "coap", "onion")
    counters = {n: mp.Array("Q", 3, lock=False) for n in names}
    proc = mp.Process(target=bench_servers.run, args=(counters, str(RUN / "cert.pem"), str(RUN / "key.pem"), 18501), daemon=True)
    proc.start()
    for n in names:
        if n != "coap":
            wait_port(bench_servers.PORTS[n][0])
    await asyncio.sleep(0.5)

    count_crypto()
    via_proxy = [dict(relays[0], port=bench_servers.PORTS["onion"][0])] + relays[1:]   # entry przez proxy liczące
    payload = bytes((i * 7 + 3) % 256 for i in range(args.payload))
    P = lambda n: bench_servers.PORTS[n][0]
    N, NO = args.n, max(6, args.n // 3)                                                  # onion z nowym obwodem jest wolniejszy
    scenarios = [
        ("HTTP/1.1, conn per message",      "http",  lambda: Http(P("http"), False, False), N),
        ("HTTP/1.1, keep-alive",            "http",  lambda: Http(P("http"), False, True), N),
        ("HTTPS, conn per message",         "https", lambda: Http(P("https"), True, False), N),
        ("HTTPS, keep-alive",               "https", lambda: Http(P("https"), True, True), N),
        ("MQTT QoS1, conn per message",     "mqtt",  lambda: Mqtt(P("mqtt"), False, False), N),
        ("MQTT QoS1, persistent",           "mqtt",  lambda: Mqtt(P("mqtt"), False, True), N),
        ("MQTTS QoS1, persistent",          "mqtts", lambda: Mqtt(P("mqtts"), True, True), N),
        ("CoAP CON (UDP)",                  "coap",  lambda: Coap(P("coap")), N),
        ("onion 3 hops, new circuit/msg",   "onion", lambda: Onion(via_proxy, 19510, 3, False), NO),
        ("onion 3 hops, circuit reused",    "onion", lambda: Onion(via_proxy, 19510, 3, True), N),
        ("onion 3 hops, reused, e2e",       "onion", lambda: Onion(via_proxy, 19511, 3, True, pub_bytes(dk)), N),
        ("onion 5 hops, new circuit/msg",   "onion", lambda: Onion(via_proxy, 19510, 5, False), NO),
        ("onion 8 hops, new circuit/msg",   "onion", lambda: Onion(via_proxy, 19510, 8, False), max(4, NO // 2)),
    ]
    if args.quick:
        scenarios = [s for s in scenarios if "8 hops" not in s[0]]
    rows = []
    for label, ctr_name, make, n in scenarios:
        res = await measure(make(), counters[ctr_name], n, payload)
        res["label"] = label
        rows.append(res)
        print(f"  {label:34s} {res['median_ms']:7.1f} ms  {res['bytes_total']:8.0f} B/msg  {res['conns']:.1f} conn", flush=True)
    proc.terminate()
    return rows


def report(rows, payload):
    hdr = ("| Protokół | opóźnienie mediana / p95 [ms] | pierwsza wiadomość [ms] | bajty na łączu / wiad. | narzut (x payload) "
           "| połączeń / wiad. | X25519 / wiad. | AES-GCM / wiad. | CPU klienta [ms/wiad.] |\n"
           "|---|---:|---:|---:|---:|---:|---:|---:|---:|\n")
    out = hdr
    for r in rows:
        out += (f"| {r['label']} | {r['median_ms']:.1f} / {r['p95_ms']:.1f} | {r['first_ms']:.1f} | {r['bytes_total']:.0f} "
                f"(↑{r['bytes_up']:.0f} ↓{r['bytes_down']:.0f}) | {r['bytes_total'] / payload:.1f} | {r['conns']:.1f} "
                f"| {r['x25519']:.1f} | {r['aead']:.1f} | {r['cpu_ms']:.1f} |\n")
    return out


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=30)
    ap.add_argument("--payload", type=int, default=64)
    ap.add_argument("--quick", action="store_true")
    args = ap.parse_args()
    print(f"Benchmark: {args.n} wiadomości po {args.payload} B (onion z nowym obwodem: {max(6, args.n // 3)})")
    try:
        rows = asyncio.run(run(args))
    finally:
        stop_all()
    md = report(rows, args.payload)
    (RUN / "bench_results.json").write_text(json.dumps(rows, indent=1))
    (RUN / "bench_results.md").write_text(md)
    print("\n" + md)
