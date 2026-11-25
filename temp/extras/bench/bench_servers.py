"""Serwery porównawcze (HTTP, HTTPS, MQTT, MQTTS, CoAP) i liczące proxy. Działają w osobnym procesie,
żeby ich CPU nie mieszało się z pomiarem klienta.

Proxy stoi przed każdym serwerem (i przed entry relayem onion) i liczy bajty widziane na łączu klienta:
  ctr[0] = bajty klient -> serwer, ctr[1] = serwer -> klient, ctr[2] = liczba przyjętych połączeń TCP.
Liczone są bajty warstwy aplikacji (z rekordami TLS), bez nagłówków TCP/IP/UDP."""
import asyncio
import os
import ssl
import struct

BIND = os.environ.get("BENCH_BIND", "127.0.0.1")   # 0.0.0.0, gdy klientem jest ESP32 w sieci


# ---------- proxy liczące ----------
async def tcp_proxy(listen_port, target_port, ctr):
    async def handle(r, w):
        ctr[2] += 1
        try:
            ur, uw = await asyncio.open_connection("127.0.0.1", target_port)
        except OSError:
            w.close()
            return

        async def pump(src, dst, idx):
            try:
                while True:
                    data = await src.read(65536)
                    if not data:
                        break
                    ctr[idx] += len(data)
                    dst.write(data)
                    await dst.drain()
                dst.write_eof()
            except (ConnectionError, OSError):
                dst.close()

        await asyncio.gather(pump(r, uw, 0), pump(ur, w, 1))
        w.close()
        uw.close()
    return await asyncio.start_server(handle, BIND, listen_port)


class _UdpUp(asyncio.DatagramProtocol):
    def __init__(self, front, client, ctr):
        self.front, self.client, self.ctr = front, client, ctr

    def datagram_received(self, data, addr):
        self.ctr[1] += len(data)
        self.front.sendto(data, self.client)


async def udp_proxy(listen_port, target_port, ctr):
    loop = asyncio.get_running_loop()
    ups = {}

    class Front(asyncio.DatagramProtocol):
        def connection_made(self, t):
            self.t = t

        def datagram_received(self, data, addr):
            ctr[0] += len(data)
            if addr not in ups:
                ups[addr] = asyncio.ensure_future(loop.create_datagram_endpoint(
                    lambda: _UdpUp(self.t, addr, ctr), remote_addr=("127.0.0.1", target_port)))
            asyncio.ensure_future(self._fwd(ups[addr], data))

        async def _fwd(self, fut, data):
            transport, _ = await fut
            transport.sendto(data)
    return await loop.create_datagram_endpoint(Front, local_addr=(BIND, listen_port))


# ---------- HTTP/1.1 ----------
async def http_handle(r, w):
    try:
        while True:
            head = await r.readuntil(b"\r\n\r\n")
            low = head.lower()
            n = 0
            if b"content-length:" in low:
                n = int(low.split(b"content-length:")[1].split(b"\r\n")[0])
            if n:
                await r.readexactly(n)
            keep = b"connection: close" not in low
            w.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: " +
                    (b"keep-alive" if keep else b"close") + b"\r\n\r\nok")
            await w.drain()
            if not keep:
                break
    except (asyncio.IncompleteReadError, ConnectionError, ssl.SSLError):
        pass
    finally:
        w.close()


# ---------- MQTT 3.1.1 (broker minimalny: CONNECT, PUBLISH QoS0/1, PINGREQ, DISCONNECT) ----------
async def mqtt_packet(r):
    b0 = (await r.readexactly(1))[0]
    mult, length = 1, 0
    while True:
        d = (await r.readexactly(1))[0]
        length += (d & 127) * mult
        mult *= 128
        if not d & 128:
            break
    return b0, (await r.readexactly(length) if length else b"")


async def mqtt_handle(r, w):
    try:
        while True:
            b0, body = await mqtt_packet(r)
            t = b0 >> 4
            if t == 1:                                   # CONNECT -> CONNACK
                w.write(b"\x20\x02\x00\x00")
            elif t == 3:                                 # PUBLISH
                if (b0 >> 1) & 3 == 1:                   # QoS 1 -> PUBACK
                    tl = struct.unpack(">H", body[:2])[0]
                    w.write(b"\x40\x02" + body[2 + tl:4 + tl])
            elif t == 12:                                # PINGREQ
                w.write(b"\xd0\x00")
            elif t == 14:                                # DISCONNECT
                break
            await w.drain()
    except (asyncio.IncompleteReadError, ConnectionError, ssl.SSLError):
        pass
    finally:
        w.close()


# ---------- CoAP (RFC 7252): CON -> ACK z kodem 2.04 ----------
class CoapServer(asyncio.DatagramProtocol):
    def connection_made(self, t):
        self.t = t

    def datagram_received(self, data, addr):
        tkl = data[0] & 0x0F
        if (data[0] >> 4) & 3 == 0:                      # CON
            self.t.sendto(bytes([0x60 | tkl, 0x44]) + data[2:4] + data[4:4 + tkl], addr)


# ---------- uruchomienie ----------
PORTS = {   # nazwa: (port proxy dla klienta, port serwera)
    "http": (19601, 19501), "https": (19602, 19502), "mqtt": (19603, 19503), "mqtts": (19604, 19504),
    "coap": (19605, 19505), "onion": (19606, None),      # onion: cel proxy podaje bench (entry relay)
}


async def main(counters, cert, key, onion_entry_port):
    sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    sctx.load_cert_chain(cert, key)
    await asyncio.start_server(http_handle, "127.0.0.1", 19501)
    await asyncio.start_server(http_handle, "127.0.0.1", 19502, ssl=sctx)
    await asyncio.start_server(mqtt_handle, "127.0.0.1", 19503)
    await asyncio.start_server(mqtt_handle, "127.0.0.1", 19504, ssl=sctx)
    await asyncio.get_running_loop().create_datagram_endpoint(CoapServer, local_addr=("127.0.0.1", 19505))
    for name in ("http", "https", "mqtt", "mqtts"):
        await tcp_proxy(PORTS[name][0], PORTS[name][1], counters[name])
    await udp_proxy(PORTS["coap"][0], PORTS["coap"][1], counters["coap"])
    await tcp_proxy(PORTS["onion"][0], onion_entry_port, counters["onion"])
    await asyncio.Event().wait()


def run(counters, cert, key, onion_entry_port):
    asyncio.run(main(counters, cert, key, onion_entry_port))


if __name__ == "__main__":
    # Tryb serwera dla klienta na ESP32:  BENCH_BIND=0.0.0.0 python3 bench_servers.py cert.pem key.pem
    # ESP32 łączy się z portami proxy (HTTP 19601, HTTPS 19602, MQTT 19603, MQTTS 19604, CoAP 19605),
    # a tu co 10 s wypisują się bajty widziane na łączu klienta (suma od startu).
    import multiprocessing as mp
    import sys
    import time
    names = ("http", "https", "mqtt", "mqtts", "coap", "onion")
    counters = {n: mp.Array("Q", 3, lock=False) for n in names}
    mp.Process(target=run, args=(counters, sys.argv[1], sys.argv[2], 1), daemon=True).start()
    while True:
        time.sleep(10)
        print(" | ".join(f"{n}: up {c[0]} down {c[1]} conns {c[2]}" for n, c in counters.items() if n != "onion"), flush=True)
