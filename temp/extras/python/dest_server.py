"""Serwer docelowy dla testów: odpowiada na każde żądanie i zamyka połączenie.

  PORT=9000 python3 dest_server.py                      tryb jawny (exit widzi treść)
  PORT=9000 DEST_KEY=<hex> python3 dest_server.py       tryb e2e: żądanie szyfrowane kluczem celu,
                                                        exit i relaye nie widzą treści ani odpowiedzi
  DIRECTORY_URL=http://host:8080 [DEST_NAME=x]          rejestruje się w katalogu jako kind "service"

Odpowiedź = b"echo: " + żądanie wielkimi literami. Cały surowy ruch widziany od strony exita
trafia do logu ("RAW <hex>"), żeby testy mogły sprawdzić, że nie ma w nim jawnego tekstu.
Założenie prototypu: całe żądanie przychodzi w jednym odczycie (małe wiadomości).
"""
import asyncio
import json
import os
import urllib.request

from onion_common import (InvalidTag, X25519PrivateKey, e2e_open_request, e2e_seal_response, pub_bytes)

dest_priv = None


def answer(request):
    if request.startswith(b"BIG"):          # test: odpowiedź dłuższa niż mieści jedna komórka
        return b"x" * 600
    return b"echo: " + request.upper()


async def handle(reader, writer):
    try:
        raw = await asyncio.wait_for(reader.read(65536), timeout=5)
        print(f"RAW {raw.hex()}", flush=True)
        if dest_priv is None:
            reply = answer(raw)
        else:
            try:
                plain, keys = e2e_open_request(dest_priv, raw)
            except (InvalidTag, ValueError) as e:
                print(f"[dest] cannot open e2e request: {e!r}", flush=True)
                return
            print(f"[dest] e2e request: {plain!r}", flush=True)
            reply = e2e_seal_response(keys, answer(plain))
        writer.write(reply)
        await writer.drain()
    except asyncio.TimeoutError:
        pass
    finally:
        writer.close()


def register(base_url, port, pub_hex):
    body = {"name": os.environ.get("DEST_NAME", f"dest{port}"), "port": port, "pub": pub_hex,
            "ver": 3, "kind": "service"}
    if os.environ.get("PUBLIC_IP"):
        body["ip"] = os.environ["PUBLIC_IP"]
    req = urllib.request.Request(base_url + "/register", json.dumps(body).encode(),
                                 {"Content-Type": "application/json"})
    urllib.request.urlopen(req, timeout=5).read()


async def main():
    global dest_priv
    port = int(os.environ.get("PORT", "9000"))
    if os.environ.get("DEST_KEY"):
        dest_priv = X25519PrivateKey.from_private_bytes(bytes.fromhex(os.environ["DEST_KEY"]))
        print(f"[dest] e2e mode, pub {pub_bytes(dest_priv).hex()}", flush=True)
    srv = await asyncio.start_server(handle, "0.0.0.0", port)
    print(f"[dest] listening on :{port}", flush=True)
    if os.environ.get("DIRECTORY_URL") and dest_priv is not None:
        await asyncio.to_thread(register, os.environ["DIRECTORY_URL"].rstrip("/"), port,
                                pub_bytes(dest_priv).hex())
    async with srv:
        await srv.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
