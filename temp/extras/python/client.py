"""Klient onion v3 (Python): biblioteka (klasa OnionCircuit) i polecenie.

  DIRECTORY_URL=http://host:8080 DEST=127.0.0.1:9000 [DEST_PUB=<hex>] [HOPS=3] \
      MESSAGE="hello" python3 client.py

  Bez katalogu:  RELAYS="ip:port@pub,ip:port@pub,ip:port@pub"  (entry pierwszy)
  DEST_PUB (klucz publiczny celu) włącza szyfrowanie end-to-end: exit i relaye nie widzą treści.
  DEST_NAME zamiast DEST_PUB: klucz celu z katalogu (kind "service").
  VERSION_OVERRIDE=9 wymusza inną wersję protokołu w CREATE (test odrzucenia).
"""
import asyncio
import json
import os
import random
import secrets
import ssl
import struct
import sys
import urllib.request

from onion_common import (
    BACKWARD, CELL_PAYLOAD, CELL_SIZE, CMD_CREATE, CMD_CREATED, CMD_DESTROY, CMD_RELAY, FORWARD, MAC,
    MAX_HOPS, NONCE, PUB, REPLY_HEADER, STATUS_OK, T_DATA, T_DATA_REPLY, T_EXTEND, T_EXTENDED, VERSION,
    InvalidTag, client_finish, client_start, decrypt_layer, e2e_open_response, e2e_seal_request,
    encrypt_layer, ip_to_int, make_cell, max_payload, parse_cell, terminal_size)


class OnionError(Exception):
    """Błąd budowy obwodu (brak odpowiedzi, zła wersja, zły klucz relaya)."""


# ---------- transport ----------
def _tls_ctx():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE     # prototyp: relaye uwierzytelnia handshake onion
    return ctx


async def tls_request(host, port, cell, expect_reply=True, timeout=10.0):
    """Wysyła jedną komórkę (nowe połączenie TLS). Zwraca odpowiedź, b"" albo None przy błędzie."""
    try:
        r, w = await asyncio.wait_for(asyncio.open_connection(host, port, ssl=_tls_ctx()), timeout=10)
        w.write(cell)
        await w.drain()
        resp = await asyncio.wait_for(r.readexactly(CELL_SIZE), timeout) if expect_reply else b""
        w.close()
        return resp
    except Exception:
        return None


def fetch_nodes(base_url, kind="relay", ver=VERSION):
    """Pobiera listę relayów (kind="relay") albo celów (kind="service") z katalogu."""
    with urllib.request.urlopen(f"{base_url.rstrip('/')}/nodes?kind={kind}&ver={ver}", timeout=5) as r:
        return json.load(r)


# ---------- obwód ----------
class OnionCircuit:
    """Obwód przez kilka relayów: klucze hopów + adres entry relaya. Użycie:

        c = OnionCircuit(); await c.build(relays); status, resp = await c.send(ip, port, b"hi"); await c.destroy()
    """

    def __init__(self):
        self.cid = None
        self.entry = None       # relay (słownik ip/port/pub), z którym rozmawiamy
        self.keys = []          # klucze hopów 0..n-1

    @property
    def hops(self):
        return len(self.keys)

    async def build(self, relays, version=VERSION):
        """CREATE do relays[0], potem EXTEND do kolejnych. relays: [{"ip","port","pub"(hex)}, ...]."""
        if not 1 <= len(relays) <= MAX_HOPS:
            raise OnionError(f"hops must be 1..{MAX_HOPS}")
        self.entry, self.keys = relays[0], []
        try:
            await self._create(relays[0], version)
            for relay in relays[1:]:
                await self._extend(relay, version)
        except ValueError as e:         # handshake nie przeszedł (zły klucz statyczny relaya)
            self.keys = []
            raise OnionError(str(e)) from e

    async def _create(self, relay, version):
        """CREATE: wersja | głębokość 0 | E  ->  CREATED: R | MAC. Wersja i klucz statyczny są weryfikowane."""
        e_priv, E = client_start()
        self.cid = secrets.randbits(32)
        raw = await tls_request(relay["ip"], relay["port"],
                                make_cell(self.cid, CMD_CREATE, bytes([version, 0]) + E))
        if not raw:
            raise OnionError(f"CREATE: no reply from {relay['ip']}:{relay['port']}")
        cid, cmd, payload = parse_cell(raw)
        if cmd == CMD_DESTROY:
            raise OnionError(f"relay speaks protocol v{payload[0]}, this client sent v{version}")
        if cmd != CMD_CREATED or cid != self.cid:
            raise OnionError("CREATE: unexpected reply")
        self.keys.append(client_finish(version, e_priv, E, bytes.fromhex(relay["pub"]),
                                       payload[:PUB], payload[PUB:PUB + MAC]))

    async def _extend(self, relay, version):
        """EXTEND: prosi ostatni hop o CREATE do nowego relaya; odpowiedź EXTENDED niesie R | MAC."""
        e_priv, E = client_start()
        terminal = bytes([T_EXTEND]) + struct.pack("<IHB", ip_to_int(relay["ip"]), relay["port"], version) + E
        rsp, _ = await self._exchange(terminal, True, 20.0)
        if rsp is None:
            raise OnionError(f"EXTEND to {relay['ip']}:{relay['port']}: no reply")
        try:
            text = self._unwrap(rsp)
        except InvalidTag:
            raise OnionError("EXTEND: reply authentication failed")
        if text[0] != T_EXTENDED:
            raise OnionError("EXTEND: unexpected reply")
        self.keys.append(client_finish(version, e_priv, E, bytes.fromhex(relay["pub"]),
                                       text[1:1 + PUB], text[1 + PUB:1 + PUB + MAC]))

    def _wrap(self, terminal):
        """Zawija tekst dla ostatniego hopa we wszystkie warstwy (od ostatniego do entry).
        Zwraca (payload 509 B, nonce najgłębszej warstwy)."""
        blob = encrypt_layer(self.keys[-1], FORWARD, terminal)
        nonce = blob[:NONCE]
        for key in reversed(self.keys[:-1]):
            blob = encrypt_layer(key, FORWARD, blob)
        assert len(blob) == CELL_PAYLOAD
        return blob, nonce

    def _unwrap(self, payload):
        """Zdejmuje warstwy odpowiedzi kluczami hopów 0..n-1. Rzuca InvalidTag, gdy któraś jest zmieniona."""
        blob = payload
        for key in self.keys:
            blob = decrypt_layer(key, BACKWARD, blob)
        return blob

    async def _exchange(self, terminal, expect_reply, timeout):
        """Wysyła tekst terminala przez obwód. Zwraca (payload odpowiedzi albo None, nonce)."""
        terminal = terminal.ljust(terminal_size(self.hops), b"\x00")
        payload, nonce = self._wrap(terminal)
        raw = await tls_request(self.entry["ip"], self.entry["port"],
                                make_cell(self.cid, CMD_RELAY, payload), expect_reply, timeout)
        if not raw:
            return None, nonce
        cid, cmd, rpayload = parse_cell(raw)
        return (rpayload if cmd == CMD_RELAY and cid == self.cid else None), nonce

    async def send(self, ip, port, data, dest_pub=None, wait=True, timeout=20.0):
        """Wysyła `data` do ip:port. dest_pub (32 B) włącza szyfrowanie end-to-end do celu.
        wait=False: bez czekania na odpowiedź. Zwraca (status, odpowiedź celu), gdzie status to:
        delivered | sent | exit_failed | no_ack | mismatch."""
        keys = None
        if dest_pub:
            data, keys = e2e_seal_request(dest_pub, data)
        if len(data) > max_payload(self.hops):
            raise ValueError(f"message too large: {len(data)} > {max_payload(self.hops)} B")
        terminal = bytes([T_DATA]) + struct.pack("<IHH", ip_to_int(ip), port, len(data)) + data
        rsp, nonce = await self._exchange(terminal, wait, timeout)
        if not wait:
            return "sent", b""
        if rsp is None:
            return "no_ack", b""
        try:
            text = self._unwrap(rsp)
        except InvalidTag:
            return "mismatch", b""
        if text[0] != T_DATA_REPLY or text[2:2 + NONCE] != nonce:
            return "mismatch", b""              # odpowiedź nie dotyczy tej wiadomości
        status, length = text[1], struct.unpack_from("<H", text, 2 + NONCE)[0]
        resp = text[REPLY_HEADER:REPLY_HEADER + length]
        if keys and resp:
            try:
                resp = e2e_open_response(keys, resp)
            except InvalidTag:
                return "mismatch", b""
        return ("delivered" if status == STATUS_OK else "exit_failed"), resp

    async def destroy(self):
        """DESTROY do entry relaya; relaye usuwają obwód i przekazują DESTROY dalej."""
        if self.keys:
            await tls_request(self.entry["ip"], self.entry["port"],
                              make_cell(self.cid, CMD_DESTROY, b""), expect_reply=False)
        self.keys = []


# ---------- polecenie ----------
def parse_relays(spec):
    out = []
    for item in spec.split(","):
        ep, pub = item.split("@")
        ip, port = ep.split(":")
        out.append({"ip": ip, "port": int(port), "pub": pub})
    return out


async def main():
    hops = int(os.environ.get("HOPS", "3"))
    if os.environ.get("DIRECTORY_URL"):
        pool = fetch_nodes(os.environ["DIRECTORY_URL"])
        if len(pool) < hops:
            sys.exit(f"directory has {len(pool)} relays, need {hops}")
        relays = random.SystemRandom().sample(pool, hops)
    else:
        relays = parse_relays(os.environ["RELAYS"])
    print("[client] path:", " > ".join(f"{r['ip']}:{r['port']}" for r in relays))

    dest_ip, dest_port = os.environ.get("DEST", "127.0.0.1:9000").split(":")
    dest_pub = bytes.fromhex(os.environ["DEST_PUB"]) if os.environ.get("DEST_PUB") else None
    if os.environ.get("DEST_NAME") and os.environ.get("DIRECTORY_URL"):
        dest_pub = bytes.fromhex(next(n["pub"] for n in fetch_nodes(os.environ["DIRECTORY_URL"], "service")
                                      if n["name"] == os.environ["DEST_NAME"]))

    circuit = OnionCircuit()
    try:
        await circuit.build(relays, int(os.environ.get("VERSION_OVERRIDE", VERSION)))
    except OnionError as e:
        sys.exit(f"[client] circuit failed: {e}")
    status, resp = await circuit.send(dest_ip, int(dest_port), os.environ.get("MESSAGE", "hello").encode(),
                                      dest_pub, wait=os.environ.get("VERIFY", "1") != "0")
    await circuit.destroy()
    print(f"[client] {status}" + (f", response: {resp!r}" if resp else ""))
    sys.exit(0 if status in ("delivered", "sent") else 3)


if __name__ == "__main__":
    asyncio.run(main())
