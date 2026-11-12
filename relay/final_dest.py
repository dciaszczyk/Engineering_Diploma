# dest.py
import asyncio, os

async def handle(reader, writer):
    peer = writer.get_extra_info("peername")
    print(f"[dest] conn from {peer}")
    total = 0
    try:
        while True:
            data = await reader.read(4096)
            if not data:
                break
            total += len(data)
            print(f"[dest] {len(data)}B: {data!r}")
            try: print(f"[dest]   text: {data.decode()}")
            except UnicodeDecodeError: pass
    finally:
        writer.close()
        try: await writer.wait_closed()
        except Exception: pass
        print(f"[dest] closed {peer} (total {total}B)")

async def main():
    port = int(os.environ.get("PORT", "9000"))
    srv = await asyncio.start_server(handle, "0.0.0.0", port)
    print(f"[dest] raw TCP listening on :{port}")
    async with srv:
        await srv.serve_forever()

if __name__ == "__main__":
    asyncio.run(main())