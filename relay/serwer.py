from fastapi import FastAPI, Request, Response
import httpx, struct, socket, os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

app = FastAPI()
MY_PORT = int(os.environ.get("PORT", "8000"))

KEYS = {
    8001: bytes.fromhex("000102030405060708090a0b0c0d0e0f"
                        "101112131415161718191a1b1c1d1e1f"),
    8002: bytes.fromhex("202122232425262728292a2b2c2d2e2f"
                        "303132333435363738393a3b3c3d3e3f"),
    8003: bytes.fromhex("404142434445464748494a4b4c4d4e4f"
                        "505152535455565758595a5b5c5d5e5f"),
}

def aes_decrypt(blob: bytes, key: bytes) -> bytes:
    iv, ct = blob[:16], blob[16:]
    d = Cipher(algorithms.AES(key), modes.CTR(iv)).decryptor()
    return d.update(ct) + d.finalize()

def parse_cell(body: bytes):
    if len(body) < 7:
        return None
    ip_raw, port, plen = struct.unpack_from("<IHB", body, 0)
    payload = body[7:7 + plen]
    ip_str = socket.inet_ntoa(struct.pack(">I", ip_raw))
    return ip_str, port, payload

@app.post("/relay")
async def relay(request: Request):
    body = await request.body()
    parsed = parse_cell(body)
    if parsed is None:
        return Response(status_code=400)
    ip_str, port, payload = parsed

    key = KEYS.get(MY_PORT)
    if key is None or len(payload) < 16:
        return Response(status_code=400)

    plain = aes_decrypt(payload, key)
    print(f"[relay:{MY_PORT}] {len(body)} B in -> {len(plain)} B plain -> {ip_str}:{port}")
    try:
        print(f"[relay:{MY_PORT}] plaintext preview: {plain[:64]!r}")
    except Exception:
        pass

    async with httpx.AsyncClient(timeout=5.0) as client:
        try:
            r = await client.post(
                f"http://{ip_str}:{port}/relay",
                content=plain,
                headers={"Content-Type": "application/octet-stream"},
            )
            print(f"[relay:{MY_PORT}] -> {r.status_code}")
        except Exception as e:
            print(f"[relay:{MY_PORT}] forward failed: {e}")
            return Response(status_code=502)

    return {"status": "ok", "forwarded": len(plain)}