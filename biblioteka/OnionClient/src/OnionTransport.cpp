#include "OnionTransport.h"
#include <WiFiClientSecure.h>

namespace onion {
namespace {

// Zapis małymi kawałkami + flush, żeby mbedTLS zdążył wysłać ostatni rekord przed stop().
bool writeAll(WiFiClientSecure& tls, const uint8_t* buf, size_t len, uint32_t timeoutMs = 10000) {
    size_t   sent     = 0;
    uint32_t deadline = millis() + timeoutMs;
    while (sent < len) {
        if (millis() > deadline) {
            ONION_LOG("write timeout %u/%u", (unsigned)sent, (unsigned)len);
            return false;
        }
        size_t chunk = (len - sent > 128) ? 128 : (len - sent);
        size_t n = tls.write(buf + sent, chunk);
        if (n > 0)               sent += n;
        else if (!tls.connected()) { ONION_LOG("peer closed during write"); return false; }
        else                     delay(5);
    }
    tls.flush();
    delay(30);
    return true;
}

//Czytanie dokładnie `len` bajtów
bool readAll(WiFiClientSecure& tls, uint8_t* buf, size_t len, uint32_t timeoutMs = 10000) {
    size_t   got      = 0;
    uint32_t deadline = millis() + timeoutMs;
    while (got < len) {
        if (millis() > deadline) {
            ONION_LOG("read timeout %u/%u", (unsigned)got, (unsigned)len);
            return false;
        }
        if (tls.available() > 0) {
            int r = tls.read(buf + got, len - got);
            if (r > 0) got += r;
        } else if (!tls.connected()) {
            ONION_LOG("peer closed during read %u/%u", (unsigned)got, (unsigned)len);
            return false;
        } else {
            delay(2);
        }
    }
    return true;
}

}  // namespace

bool exchangeCell(const Relay& relay, const Cell& out, Cell* reply) {
    WiFiClientSecure tls;
    tls.setInsecure();
    tls.setTimeout(10);            
    tls.setHandshakeTimeout(15); 
    tls.setNoDelay(true);

    IPAddress ip = u32ToIp(relay.ip);
    if (!tls.connect(ip, relay.port)) {
        ONION_LOG("TLS connect to %s (%s:%u) failed", relay.name, ip.toString().c_str(), relay.port);
        return false;
    }

    bool ok = writeAll(tls, (const uint8_t*)&out, sizeof(out)) &&
              (reply == nullptr || readAll(tls, (uint8_t*)reply, sizeof(*reply)));
    tls.stop();
    return ok;
}

}  // namespace onion
