# relay.py
import asyncio, os, ssl, socket, secrets, struct, traceback
from dataclasses import dataclass
from typing import Optional
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

CELL_SIZE         = 514
CELL_PAYLOAD_SIZE = 509
CMD_CREATE, CMD_CREATED, CMD_RELAY, CMD_DESTROY = 0x01, 0x02, 0x03, 0x04
RCMD_EXTEND, RCMD_EXTENDED, RCMD_DATA = 0x10, 0x11, 0x12
IV_SIZE, KEY_SIZE, PUB_SIZE, HMAC_SIZE = 16, 32, 32, 32
HDR = 9  # targetIP(4) | targetPort(2) | relayCmd(1) | payloadLen(2)


@dataclass
class CircuitState:
    hop_key: bytes
    next_ip: Optional[str] = None
    next_port: Optional[int] = None
    next_circuit_id: Optional[int] = None


circuits: dict[int, CircuitState] = {}


# ---------- crypto ----------
def aes_encrypt(plain: bytes, key: bytes) -> bytes:
    iv = secrets.token_bytes(IV_SIZE)
    enc = Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor()
    return iv + enc.update(plain) + enc.finalize()


def aes_decrypt(blob: bytes, key: bytes) -> bytes:
    iv, ct = blob[:IV_SIZE], blob[IV_SIZE:]
    dec = Cipher(algorithms.AES(key), modes.CTR(iv)).decryptor()
    return dec.update(ct) + dec.finalize()


def derive_key(shared: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=KEY_SIZE, salt=None,
                info=b"onion-hop-v1").derive(shared)


def hmac_sha256(key: bytes, data: bytes) -> bytes:
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(data)
    return h.finalize()


# ---------- cell ----------
def build_cell(cid: int, cmd: int, payload: bytes) -> bytes:
    if len(payload) < CELL_PAYLOAD_SIZE:
        payload = payload + b"\x00" * (CELL_PAYLOAD_SIZE - len(payload))
    return struct.pack("<IB", cid, cmd) + payload[:CELL_PAYLOAD_SIZE]


def parse_relay_header(plain: bytes):
    if len(plain) < HDR:
        return None
    ip_raw, port, rcmd, plen = struct.unpack_from("<IHBH", plain, 0)
    if HDR + plen > len(plain):
        return None
    return (socket.inet_ntoa(struct.pack(">I", ip_raw)),
            port, rcmd, plain[HDR:HDR + plen])


# ---------- TLS helpers ----------
def tls_client_ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # prototype only
    return ctx


async def tls_request(host: str, port: int, cell: bytes,
                      timeout: float = 10.0) -> Optional[bytes]:
    try:
        r, w = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=tls_client_ctx()),
            timeout=timeout,
        )
        w.write(cell)
        await w.drain()
        resp = await asyncio.wait_for(r.readexactly(CELL_SIZE), timeout=timeout)
        w.close()
        try: await w.wait_closed()
        except Exception: pass
        return resp
    except Exception as e:
        print(f"[relay] tls_request {host}:{port} err: {e}")
        return None


# ---------- handlers ----------
async def handle_create(writer, cid: int, payload: bytes):
    client_pub_raw = payload[:PUB_SIZE]
    relay_priv = X25519PrivateKey.generate()
    relay_pub_raw = relay_priv.public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw)
    shared = relay_priv.exchange(X25519PublicKey.from_public_bytes(client_pub_raw))
    hop_key = derive_key(shared)
    circuits[cid] = CircuitState(hop_key=hop_key)

    proof = hmac_sha256(hop_key, client_pub_raw + relay_pub_raw)
    created = relay_pub_raw + proof
    writer.write(build_cell(cid, CMD_CREATED, created))
    await writer.drain()
    print(f"[relay] CREATE cid={cid:#x} -> CREATED")


async def do_create_for_extend(next_ip: str, next_port: int,
                               client_eph_pub: bytes):
    """Wyślij CREATE do nowego relay, odbierz CREATED, zwróć (eph_pub||hmac)."""
    new_cid = secrets.randbits(32)
    create_payload = client_eph_pub + b"\x00" * (CELL_PAYLOAD_SIZE - PUB_SIZE)
    cell = build_cell(new_cid, CMD_CREATE, create_payload)
    resp = await tls_request(next_ip, next_port, cell)
    if resp is None:
        return None
    resp_cid, resp_cmd = struct.unpack_from("<IB", resp, 0)
    if resp_cmd != CMD_CREATED or resp_cid != new_cid:
        print(f"[relay] EXTEND got bad CREATED (cmd={resp_cmd:#x}, cid={resp_cid:#x})")
        return None
    return new_cid, resp[5:5 + PUB_SIZE + HMAC_SIZE]


async def handle_relay(reader, writer, cid: int, payload: bytes):
    state = circuits.get(cid)
    if state is None:
        print(f"[relay] RELAY unknown cid={cid:#x}")
        return
    if len(payload) < IV_SIZE:
        return

    plain = aes_decrypt(payload, state.hop_key)
    hdr = parse_relay_header(plain)
    if hdr is None:
        return
    t_ip, t_port, rcmd, inner = hdr
    print(f"[relay] RELAY cid={cid:#x} rcmd={rcmd:#x} -> {t_ip}:{t_port} ({len(inner)}B)")

    if rcmd == RCMD_EXTEND:
        # inner = eph_pub(32) + padding
        eph_pub = inner[:PUB_SIZE]
        result = await do_create_for_extend(t_ip, t_port, eph_pub)
        if result is None:
            return
        new_cid, response_payload = result
        state.next_ip, state.next_port, state.next_circuit_id = t_ip, t_port, new_cid
        # wrap EXTENDED
        out_plain = struct.pack("<IHBH", 0, 0, RCMD_EXTENDED,
                                len(response_payload)) + response_payload
        out_plain = out_plain.ljust(CELL_PAYLOAD_SIZE - IV_SIZE, b"\x00")
        enc = aes_encrypt(out_plain, state.hop_key)
        writer.write(build_cell(cid, CMD_RELAY, enc))
        await writer.drain()
        print(f"[relay] EXTEND -> {t_ip}:{t_port} ok, next_cid={new_cid:#x}")

    elif rcmd == RCMD_DATA:
        if state.next_circuit_id is None:
            # exit: raw TCP do celu
            try:
                s = socket.create_connection((t_ip, t_port), timeout=5.0)
                s.sendall(inner)
                s.close()
                print(f"[relay] EXIT -> {t_ip}:{t_port} ({len(inner)}B)")
            except Exception as e:
                print(f"[relay] EXIT failed: {e}")
            return

        # forward do następnego hopa
        forward_cell = build_cell(state.next_circuit_id, CMD_RELAY, inner)
        resp = await tls_request(state.next_ip, state.next_port, forward_cell)
        if resp is None:
            return
        resp_cid, resp_cmd = struct.unpack_from("<IB", resp, 0)
        if resp_cmd != CMD_RELAY:
            return
        # wrap całym payloadem z powrotem do poprzedniego hopa (przycięte do 509)
        wrapped = aes_encrypt(resp[5:], state.hop_key)
        writer.write(build_cell(cid, CMD_RELAY, wrapped[:CELL_PAYLOAD_SIZE]))
        await writer.drain()
        print(f"[relay] forwarded cid={cid:#x} -> {state.next_ip}:{state.next_port} cid={state.next_circuit_id:#x}")


async def handle_client(reader, writer):
    peer = writer.get_extra_info("peername")
    print(f"[relay] TLS conn from {peer}")
    try:
        while True:
            try:
                cell = await asyncio.wait_for(
                    reader.readexactly(CELL_SIZE), timeout=30.0)
            except (asyncio.TimeoutError, asyncio.IncompleteReadError):
                break
            cid, cmd = struct.unpack_from("<IB", cell, 0)
            payload = cell[5:]
            print(f"[relay] cell cid={cid:#x} cmd={cmd:#x}")
            if cmd == CMD_CREATE:
                await handle_create(writer, cid, payload)
            elif cmd == CMD_RELAY:
                await handle_relay(reader, writer, cid, payload)
            elif cmd == CMD_DESTROY:
                circuits.pop(cid, None)
                break
            else:
                print(f"[relay] unknown cmd {cmd:#x}")
    except Exception:
        traceback.print_exc()
    finally:
        writer.close()
        try: await writer.wait_closed()
        except Exception: pass
        print(f"[relay] closed {peer}")


async def main():
    port = int(os.environ.get("PORT", "8001"))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(os.environ.get("CERT", "cert.pem"),
                        os.environ.get("KEY",  "key.pem"))
    srv = await asyncio.start_server(handle_client, "0.0.0.0", port, ssl=ctx)
    print(f"[relay] TLS listening on :{port}")
    async with srv:
        await srv.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())