from fastapi import FastAPI, Request, Response
import httpx, struct, socket, os

app = FastAPI()
MY_PORT = int(os.environ.get("PORT", "8000"))

def parse_cell(body: bytes):
    if len(body) < 7:
        return None
    target_ip_raw, target_port, payload_len = struct.unpack_from("<IHB", body, 0)
    payload = body[7:7 + payload_len]
    ip_str = socket.inet_ntoa(struct.pack(">I", target_ip_raw))
    return ip_str, target_port, payload

@app.post("/relay")
async def relay(request: Request):
    body = await request.body()
    parsed = parse_cell(body)
    if parsed is None:
        return Response(status_code=400)

    ip_str, port, payload = parsed
    print(f"[relay:{MY_PORT}] {len(body)} B in -> {len(payload)} B -> {ip_str}:{port}")

    async with httpx.AsyncClient(timeout=5.0) as client:
        try:
            r = await client.post(
                f"http://{ip_str}:{port}/relay",
                content=payload,
                headers={"Content-Type": "application/octet-stream"},
            )
            print(f"[relay:{MY_PORT}] -> {r.status_code}")
        except Exception as e:
            print(f"[relay:{MY_PORT}] forward failed: {e}")
            return Response(status_code=502)

    return {"status": "ok", "forwarded": len(payload)}