#include "OnionTransport.h"
#include <WiFiClient.h>
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

// Czytanie dokładnie `len` bajtów, bez wieszania się w nieskończoność.
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

bool exchangeCell(const Relay& relay, const Cell& out, Cell* reply, uint32_t replyTimeoutMs) {
    WiFiClientSecure tls;
    tls.setInsecure();
    tls.setTimeout(10);            // sekundy
    tls.setHandshakeTimeout(15);   // sekundy
    tls.setNoDelay(true);

    IPAddress ip = u32ToIp(relay.ip);
    if (!tls.connect(ip, relay.port)) {
        ONION_LOG("TLS connect to %s (%s:%u) failed", relay.name, ip.toString().c_str(), relay.port);
        return false;
    }

    bool ok = writeAll(tls, (const uint8_t*)&out, sizeof(out)) &&
              (reply == nullptr || readAll(tls, (uint8_t*)reply, sizeof(*reply), replyTimeoutMs));
    tls.stop();
    return ok;
}

bool tcpExchange(uint32_t ip, uint16_t port, const uint8_t* req, size_t len,
                 uint8_t* resp, size_t cap, size_t* respLen, uint32_t timeoutMs) {
    *respLen = 0;
    WiFiClient client;   // mimo nazwy działa na każdym interfejsie lwIP, także Ethernet
    if (!client.connect(u32ToIp(ip), port, timeoutMs)) {
        ONION_LOG("TCP connect to %s:%u failed", u32ToIp(ip).toString().c_str(), port);
        return false;
    }
    if (client.write(req, len) != len) { client.stop(); return false; }
    client.flush();

    uint32_t deadline = millis() + timeoutMs;
    while (*respLen < cap && (int32_t)(millis() - deadline) < 0) {
        if (client.available() > 0) {
            int r = client.read(resp + *respLen, cap - *respLen);
            if (r > 0) *respLen += r;
        } else if (!client.connected()) {
            break;                      // cel zamknął połączenie: odpowiedź kompletna
        } else {
            delay(5);
        }
    }
    client.stop();
    return true;
}

}  // namespace onion
