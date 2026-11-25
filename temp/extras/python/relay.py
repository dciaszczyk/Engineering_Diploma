"""Relay onion v3 (Python). Uruchom:  RELAY_STATIC_KEY=<hex z keygen.py> PORT=8001 python3 relay.py

Zmienne: PORT, RELAY_STATIC_KEY (wymagana), CERT/KEY (TLS, domyślnie cert.pem/key.pem),
         DIRECTORY_URL (np. http://host:8080; relay sam się rejestruje), RELAY_NAME, PUBLIC_PORT,
         PUBLIC_IP (adres, pod którym klienci widzą ten relay; domyślnie ustala go katalog z połączenia).

Co robi relay (format komórek: patrz onion_common.py):
  CREATE   -> handshake, zapamiętuje klucz hopa i głębokość pod id obwodu, odpowiada CREATED
  RELAY    -> zdejmuje swoją warstwę (AES-GCM; zmieniona warstwa = porzucenie komórki), potem
              * ma następny hop: przekazuje zdjętą warstwę dalej pod id obwodu na następnym łączu
                i odsyła odpowiedź owiniętą własną warstwą,
              * nie ma następnego hopa: wykonuje polecenie (EXTEND albo DATA = exit do celu)
  DESTROY  -> usuwa obwód i przekazuje DESTROY dalej
Jedno połączenie TLS = jedna komórka; po odpowiedzi (lub błędzie) relay zamyka połączenie.
"""
import asyncio
import json
import os
import secrets
import ssl
import struct
import traceback
import urllib.request
from dataclasses import dataclass
from typing import Optional

from onion_common import (
    BACKWARD, CELL_SIZE, CMD_CREATE, CMD_CREATED, CMD_DESTROY, CMD_RELAY, DATA_HEADER, FORWARD,
    LAYER_OVERHEAD, MAC, MAX_HOPS, NONCE, PUB, REPLY_HEADER, STATUS_FAILED, STATUS_OK, T_DATA,
    T_DATA_REPLY, T_EXTEND, T_EXTENDED, VERSION, InvalidTag, decrypt_layer, encrypt_layer, layer_size,
    make_cell, parse_cell, pub_bytes, server_handshake)
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

EXIT_TIMEOUT = 3.0          # jak długo exit czeka na odpowiedź celu
FORWARD_TIMEOUT = 20.0      # jak długo czekamy na odpowiedź następnego hopa


@dataclass
class Circuit:
    key: bytes                          # klucz tego hopa
    depth: int                          # pozycja w obwodzie (0 = entry)
    next_ip: Optional[str] = None       # następny hop (ustawiany przez EXTEND)
    next_port: Optional[int] = None
    next_cid: Optional[int] = None      # id tego obwodu na łączu do następnego hopa


circuits = {}                           # id obwodu (od poprzedniego hopa) -> Circuit
static_priv = None                      # statyczny klucz tożsamości relaya
static_pub = b""


# ---------- sieć ----------
def tls_client_ctx():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE     # prototyp: relaye uwierzytelnia handshake onion, nie TLS
    return ctx


async def tls_request(host, port, cell, expect_reply=True, timeout=FORWARD_TIMEOUT):
    """Wysyła jedną komórkę do relaya (nowe połączenie TLS). Zwraca komórkę zwrotną,
    b"" gdy odpowiedzi nie oczekujemy, albo None przy błędzie."""
    try:
        r, w = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=tls_client_ctx()), timeout=10)
        w.write(cell)
        await w.drain()
        resp = await asyncio.wait_for(r.readexactly(CELL_SIZE), timeout) if expect_reply else b""
        w.close()
        return resp
    except Exception as e:
        print(f"[relay] request to {host}:{port} failed: {e!r}", flush=True)
        return None


async def exit_exchange(ip, port, data, max_resp):
    """Exit: wysyła dane do celu zwykłym TCP i zbiera odpowiedź (do EOF, max_resp albo EXIT_TIMEOUT).
    Zwraca (status, odpowiedź). Cel powinien zamknąć połączenie po odpowiedzi."""
    try:
        r, w = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=5)
    except Exception as e:
        print(f"[relay] exit connect {ip}:{port} failed: {e!r}", flush=True)
        return STATUS_FAILED, b""
    resp = b""
    try:
        w.write(data)
        await w.drain()
        loop = asyncio.get_running_loop()
        deadline = loop.time() + EXIT_TIMEOUT
        while len(resp) < max_resp and deadline - loop.time() > 0:
            chunk = await asyncio.wait_for(r.read(max_resp - len(resp)), deadline - loop.time())
            if not chunk:
                break
            resp += chunk
    except asyncio.TimeoutError:
        pass
    except Exception as e:
        print(f"[relay] exit io {ip}:{port}: {e!r}", flush=True)
    finally:
        w.close()
    return STATUS_OK, resp


def reply_cell(cid, c, text):
    """Odpowiedź z tego hopa: dopełnia tekst zerami do rozmiaru warstwy, szyfruje (kierunek wstecz)."""
    text = text.ljust(layer_size(c.depth) - LAYER_OVERHEAD, b"\x00")
    return make_cell(cid, CMD_RELAY, encrypt_layer(c.key, BACKWARD, text))


# ---------- obsługa komórek ----------
async def handle_create(writer, cid, payload):
    """CREATE: wersja | głębokość | E. Przy obcej wersji odpowiada DESTROY z wersją relaya."""
    version, depth, E = payload[0], payload[1], payload[2:2 + PUB]
    if version != VERSION:
        print(f"[relay] CREATE {cid:#x}: version {version} not supported (this relay: {VERSION})", flush=True)
        writer.write(make_cell(cid, CMD_DESTROY, bytes([VERSION])))
        await writer.drain()
        return
    if depth >= MAX_HOPS:
        return
    try:
        R, mac, key = server_handshake(version, E, static_priv)
    except ValueError as e:
        print(f"[relay] CREATE {cid:#x} rejected: {e}", flush=True)
        return
    circuits[cid] = Circuit(key=key, depth=depth)
    writer.write(make_cell(cid, CMD_CREATED, R + mac))
    await writer.drain()
    print(f"[relay] CREATE {cid:#x} depth={depth} -> CREATED", flush=True)


async def handle_destroy(cid):
    """DESTROY: usuwa obwód i przekazuje DESTROY do następnego hopa (pod jego id obwodu)."""
    c = circuits.pop(cid, None)
    if c is None:
        print(f"[relay] DESTROY unknown circuit {cid:#x}", flush=True)
        return
    print(f"[relay] DESTROY {cid:#x}", flush=True)
    if c.next_cid is not None:
        await tls_request(c.next_ip, c.next_port, make_cell(c.next_cid, CMD_DESTROY, b""), expect_reply=False)


async def handle_relay(writer, cid, payload):
    """RELAY: zdejmij swoją warstwę (AES-GCM) i przekaż dalej albo wykonaj polecenie."""
    c = circuits.get(cid)
    if c is None:
        print(f"[relay] RELAY unknown circuit {cid:#x}", flush=True)
        return
    try:
        plain = decrypt_layer(c.key, FORWARD, payload[:layer_size(c.depth)])
    except InvalidTag:
        print(f"[relay] RELAY {cid:#x}: layer authentication failed, dropped", flush=True)
        return

    if c.next_cid is not None:
        await forward(writer, cid, c, plain)
    elif plain[0] == T_EXTEND:
        await do_extend(writer, cid, c, plain)
    elif plain[0] == T_DATA:
        await do_data(writer, cid, c, plain, payload[:NONCE])
    else:
        print(f"[relay] unknown terminal command {plain[0]:#x}", flush=True)


async def forward(writer, cid, c, inner):
    """Środek obwodu: zdjęta warstwa to cała warstwa następnego hopa; odpowiedź owijamy swoją."""
    rsp = await tls_request(c.next_ip, c.next_port, make_cell(c.next_cid, CMD_RELAY, inner))
    if not rsp:
        return
    rcid, rcmd, rpayload = parse_cell(rsp)
    if rcmd != CMD_RELAY or rcid != c.next_cid:
        return
    blob = rpayload[:layer_size(c.depth + 1)]
    writer.write(make_cell(cid, CMD_RELAY, encrypt_layer(c.key, BACKWARD, blob)))
    await writer.drain()
    print(f"[relay] forwarded {cid:#x} -> {c.next_ip}:{c.next_port}", flush=True)


async def do_extend(writer, cid, c, plain):
    """EXTEND: CREATE do nowego relaya w imieniu klienta; odpowiedź wraca jako EXTENDED."""
    ip_raw, port, version = struct.unpack_from("<IHB", plain, 1)
    E = plain[8:8 + PUB]
    ip = ".".join(str(b) for b in struct.pack(">I", ip_raw))
    new_cid = secrets.randbits(32)
    rsp = await tls_request(ip, port, make_cell(new_cid, CMD_CREATE, bytes([version, c.depth + 1]) + E))
    if not rsp:
        return
    rcid, rcmd, rpayload = parse_cell(rsp)
    if rcmd == CMD_DESTROY:
        print(f"[relay] EXTEND: next relay speaks protocol v{rpayload[0]}", flush=True)
        return
    if rcmd != CMD_CREATED or rcid != new_cid:
        return
    c.next_ip, c.next_port, c.next_cid = ip, port, new_cid
    writer.write(reply_cell(cid, c, bytes([T_EXTENDED]) + rpayload[:PUB + MAC]))
    await writer.drain()
    print(f"[relay] EXTEND -> {ip}:{port} ok", flush=True)


async def do_data(writer, cid, c, plain, nonce):
    """DATA w ostatnim hopie (exit): dostarcz do celu i odeślij DATA_REPLY z odpowiedzią celu.
    `nonce` (nonce naszej warstwy) odsyłamy klientowi, żeby wiązał odpowiedź z wiadomością."""
    ip_raw, port, length = struct.unpack_from("<IHH", plain, 1)
    data = plain[DATA_HEADER:DATA_HEADER + length]
    ip = ".".join(str(b) for b in struct.pack(">I", ip_raw))
    max_resp = layer_size(c.depth) - LAYER_OVERHEAD - REPLY_HEADER
    status, resp = await exit_exchange(ip, port, data, max_resp)
    print(f"[relay] EXIT {ip}:{port} {len(data)}B -> status={status} reply={len(resp)}B", flush=True)
    text = bytes([T_DATA_REPLY, status]) + nonce + struct.pack("<H", len(resp)) + resp
    writer.write(reply_cell(cid, c, text))
    await writer.drain()


async def handle_client(reader, writer):
    """Jedno połączenie = jedna komórka."""
    try:
        raw = await asyncio.wait_for(reader.readexactly(CELL_SIZE), timeout=30)
        cid, cmd, payload = parse_cell(raw)
        if cmd == CMD_CREATE:
            await handle_create(writer, cid, payload)
        elif cmd == CMD_RELAY:
            await handle_relay(writer, cid, payload)
        elif cmd == CMD_DESTROY:
            await handle_destroy(cid)
        else:
            print(f"[relay] unknown cmd {cmd:#x}", flush=True)
    except (asyncio.TimeoutError, asyncio.IncompleteReadError):
        pass
    except Exception:
        traceback.print_exc()
    finally:
        writer.close()


# ---------- rejestracja w katalogu ----------
def post_json(url, body):
    req = urllib.request.Request(url, json.dumps(body).encode(), {"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=5) as r:
        return r.status == 200


async def register_loop(base_url, port):
    """Rejestruje relay w katalogu i odświeża wpis co minutę (katalog sam ustala nasz adres IP)."""
    body = {"name": os.environ.get("RELAY_NAME", f"relay{port}"), "port": port,
            "pub": static_pub.hex(), "ver": VERSION, "kind": "relay"}
    if os.environ.get("PUBLIC_IP"):             # adres widoczny dla klientów w LAN (domyślnie katalog bierze go z połączenia)
        body["ip"] = os.environ["PUBLIC_IP"]
    ok = False
    while True:
        try:
            await asyncio.to_thread(post_json, base_url + "/register", body)
            if not ok:
                print(f"[relay] registered in directory {base_url}", flush=True)
            ok = True
            await asyncio.sleep(60)
        except Exception as e:
            ok = False
            print(f"[relay] directory registration failed: {e!r}", flush=True)
            await asyncio.sleep(5)


async def main():
    global static_priv, static_pub
    port = int(os.environ.get("PORT", "8001"))
    key_hex = os.environ.get("RELAY_STATIC_KEY")
    if not key_hex:
        raise SystemExit("ustaw RELAY_STATIC_KEY (hex, wynik keygen.py)")
    static_priv = X25519PrivateKey.from_private_bytes(bytes.fromhex(key_hex))
    static_pub = pub_bytes(static_priv)
    print(f"[relay] protocol v{VERSION}, static pub: {static_pub.hex()}", flush=True)

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(os.environ.get("CERT", "cert.pem"), os.environ.get("KEY", "key.pem"))
    srv = await asyncio.start_server(handle_client, "0.0.0.0", port, ssl=ctx)
    print(f"[relay] TLS listening on :{port}", flush=True)

    if os.environ.get("DIRECTORY_URL"):
        asyncio.create_task(register_loop(os.environ["DIRECTORY_URL"].rstrip("/"),
                                          int(os.environ.get("PUBLIC_PORT", port))))
    async with srv:
        await srv.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
