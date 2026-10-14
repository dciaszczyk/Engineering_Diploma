from fastapi import FastAPI, Request
import os

app = FastAPI()
MY_PORT = int(os.environ.get("PORT", "9000"))

@app.post("/relay")
async def receive(request: Request):
    body = await request.body()
    print(f"[final:{MY_PORT}] got {len(body)} B: {body!r}")
    try:
        print(f"[final:{MY_PORT}] text: {body.decode()}")
    except UnicodeDecodeError:
        pass
    return {"ok": True}