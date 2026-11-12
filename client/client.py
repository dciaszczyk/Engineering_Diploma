# client/client.py
import asyncio, os, ssl, socket, struct, secrets, sys
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

CELL_SIZE         = 514
CELL_PAYLOAD_SIZE = 509
CMD_CREATE, CMD_CREATED, CMD_RELAY, CMD_DESTROY = 0x01, 0x02, 0x03, 0x04
RCMD_EXTEND, RCMD_EXTENDED, RCMD_DATA = 0x10, 0x11, 0x12
IV_SIZE, KEY_SIZE, PUB_SIZE, HMAC_SIZE = 16, 32, 32, 32
HDR = 9


# ---- crypto (identyczne z serwer.py) ----
def aes_encrypt(plain, key):
    iv = secrets.token_bytes(IV_SIZE)
    enc = Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor()
    return iv + enc.update(plain) + enc.finalize()

def aes_decrypt(blob, key):
    iv, ct = blob[:IV_SIZE], blob[IV_SIZE:]
    dec = Cipher(algorithms.AES(key), modes.CTR(iv)).decryptor()
    return dec.update(ct) + dec.finalize()

def derive_key(shared):
    return HKDF(algorithm=hashes.SHA256(), length=KEY_SIZE, salt=None,
                info=b"onion-hop-v1").derive(shared)

def hmac_sha256(key, data):
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(data)
    return h.finalize()


# ---- wire helpers ----
def ip_to_wire(ip_str):
    """IP string -> 4 bajty little-endian (zgodnie z C++ memcpy)."""
    return socket.inet_aton(ip_str)[::-1]

def build_cell(cid, cmd, payload):
    if len(payload) < CELL_PAYLOAD_SIZE:
        payload = payload + b"\x00" * (CELL_PAYLOAD_SIZE - len(payload))
    return struct.pack("<IB", cid, cmd) + payload[:CELL_PAYLOAD_SIZE]


# ---- TLS ----
def tls_ctx():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx

async def send_recv(ip, port, cell, timeout=10.0):
    r, w = await asyncio.open_connection(ip, port, ssl=tls_ctx())
    w.write(cell)
    await w.drain()
    resp = await asyncio.wait_for(r.readexactly(CELL_SIZE), timeout)
    w.close()
    try: await w.wait_closed()
    except Exception: pass
    return resp

async def send_only(ip, port, cell):
    r, w = await asyncio.open_connection(ip, port, ssl=tls_ctx())
    w.write(cell)
    await w.drain()
    w.close()
    try: await w.wait_closed()
    except Exception: pass


# ---- circuit ----
class Hop:
    __slots__ = ("circuit_id", "hop_key", "ip", "port")
    def __init__(self, cid, key, ip, port):
        self.circuit_id = cid
        self.hop_key = key
        self.ip = ip
        self.port = port


async def create_hop(ip, port):
    eph = X25519PrivateKey.generate()
    eph_pub = eph.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    cid = secrets.randbits(32)
    resp = await send_recv(ip, port, build_cell(cid, CMD_CREATE, eph_pub))
    resp_cid, resp_cmd = struct.unpack_from("<IB", resp, 0)
    if resp_cmd != CMD_CREATED or resp_cid != cid:
        raise RuntimeError(f"CREATE failed: cmd={resp_cmd:#x} cid={resp_cid:#x}")
    relay_pub = resp[5:5 + PUB_SIZE]
    recv_hmac = resp[5 + PUB_SIZE:5 + PUB_SIZE + HMAC_SIZE]
    shared = eph.exchange(X25519PublicKey.from_public_bytes(relay_pub))
    hop_key = derive_key(shared)
    if hmac_sha256(hop_key, eph_pub + relay_pub) != recv_hmac:
        raise RuntimeError("CREATED hmac mismatch")
    print(f"[client] CREATE {ip}:{port} ok cid={cid:#x}")
    return Hop(cid, hop_key, ip, port)


async def extend(entry_ip, entry_port, established, new_ip, new_port):
    eph = X25519PrivateKey.generate()
    eph_pub = eph.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    # warstwa wewnętrzna: dla established[-1]
    header = struct.pack("<IHBH", 0, 0, RCMD_EXTEND, PUB_SIZE)
    header = ip_to_wire(new_ip) + struct.pack("<HBH", new_port, RCMD_EXTEND, PUB_SIZE)
    inner = header + eph_pub
    cipher = aes_encrypt(inner, established[-1].hop_key)

    # warstwy zewnętrzne
    for i in range(len(established) - 2, -1, -1):
        next_hop = established[i + 1]
        hdr = ip_to_wire(next_hop.ip) + struct.pack("<HBH", next_hop.port, RCMD_DATA, len(cipher))
        cipher = aes_encrypt(hdr + cipher, established[i].hop_key)

    resp = await send_recv(entry_ip, entry_port,
                           build_cell(established[0].circuit_id, CMD_RELAY, cipher))

    # odszyfruj warstwa po warstwie
    buf = resp[5:]
    for hop in established:
        buf = aes_decrypt(buf, hop.hop_key)
    if len(buf) < HDR:
        raise RuntimeError("EXTENDED response too short")
    _, _, rcmd, plen = struct.unpack_from("<IHBH", buf, 0)
    if rcmd != RCMD_EXTENDED:
        raise RuntimeError(f"expected EXTENDED, got {rcmd:#x}")
    payload = buf[HDR:HDR + plen]
    relay_pub = payload[:PUB_SIZE]
    recv_hmac = payload[PUB_SIZE:PUB_SIZE + HMAC_SIZE]
    shared = eph.exchange(X25519PublicKey.from_public_bytes(relay_pub))
    new_key = derive_key(shared)
    if hmac_sha256(new_key, eph_pub + relay_pub) != recv_hmac:
        raise RuntimeError("EXTENDED hmac mismatch")
    print(f"[client] EXTEND {new_ip}:{new_port} ok")
    return Hop(None, new_key, new_ip, new_port)


async def send_data(entry_ip, entry_port, established, dest_ip, dest_port, message):
    body = message.encode()
    hdr = ip_to_wire(dest_ip) + struct.pack("<HBH", dest_port, RCMD_DATA, len(body))
    cipher = aes_encrypt(hdr + body, established[-1].hop_key)
    for i in range(len(established) - 2, -1, -1):
        nxt = established[i + 1]
        hdr = ip_to_wire(nxt.ip) + struct.pack("<HBH", nxt.port, RCMD_DATA, len(cipher))
        cipher = aes_encrypt(hdr + cipher, established[i].hop_key)
    await send_only(entry_ip, entry_port,
                    build_cell(established[0].circuit_id, CMD_RELAY, cipher))
    print(f"[client] DATA sent ({len(body)} B) via {len(established)} hop(s)")


# ---- main ----
def parse_ep(s):
    host, port = s.rsplit(":", 1)
    return host.strip(), int(port)


async def main():
    relays_str = os.environ.get("RELAYS", "127.0.0.1:8001,127.0.0.1:8002,127.0.0.1:8003")
    dest_str   = os.environ.get("DEST", "127.0.0.1:9000")
    message    = os.environ.get("MESSAGE", "hello world")

    relays = [parse_ep(x) for x in relays_str.split(",") if x.strip()]
    dest_ip, dest_port = parse_ep(dest_str)
    if not relays:
        raise SystemExit("no relays configured")

    print(f"[client] path: {relays} -> {dest_ip}:{dest_port}")

    established = []
    # hop 1: CREATE bezpośrednio do entry
    established.append(await create_hop(*relays[0]))
    # kolejne: EXTEND przez entry
    for ip, port in relays[1:]:
        established.append(await extend(relays[0][0], relays[0][1],
                                        established, ip, port))

    await send_data(relays[0][0], relays[0][1], established,
                    dest_ip, dest_port, message)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except Exception as e:
        print(f"[client] error: {e}", file=sys.stderr)
        sys.exit(1)