#include "OnionCircuit.h"
#include "OnionCrypto.h"
#include "OnionTransport.h"
#include <esp_random.h>

namespace onion {
namespace {

// Komórka z ładunkiem dopełnionym losowymi bajtami.
void makeCell(Cell& cell, uint32_t id, uint8_t cmd, const uint8_t* payload, size_t len) {
    cell.circuitId = id;
    cell.command   = cmd;
    memcpy(cell.payload, payload, len);
    esp_fill_random(cell.payload + len, CELL_PAYLOAD_SIZE - len);
}

// Warstwa przed zaszyfrowaniem: [RelayHeader][payload].
size_t packLayer(uint8_t* out, uint32_t ip, uint16_t port, uint8_t cmd,
                 const uint8_t* payload, size_t len) {
    RelayHeader h{ip, port, cmd, (uint16_t)len};
    memcpy(out, &h, sizeof(h));
    memcpy(out + sizeof(h), payload, len);
    return sizeof(h) + len;
}

}  // namespace

//Budowa obwodu

void Circuit::reset() {
    id_   = 0;
    hops_ = 0;
    memset(keys_, 0, sizeof(keys_));
}

bool Circuit::build(const Relay* path, uint8_t hops) {
    reset();
    if (hops == 0 || hops > MAX_HOPS) return false;

    if (!create(path[0])) return false;
    for (uint8_t i = 1; i < hops; i++) {
        if (!extend(path[i])) { reset(); return false; }
    }
    ONION_LOG("circuit ready, %u hops", (unsigned)hops_);
    return true;
}

// CREATE: bezpośredni handshake z entry relayem.
//CREATE  { ephPub, losowe wypełnienie }
//zwrotka CREATED { relayEphPub, MAC }
bool Circuit::create(const Relay& first) {
    Handshake hs;
    if (!hs.start()) return false;

    Cell req, rsp;
    makeCell(req, esp_random(), CMD_CREATE, hs.pub, sizeof(hs.pub));
    if (!exchangeCell(first, req, &rsp)) return false;

    if (rsp.command != CMD_CREATED || rsp.circuitId != req.circuitId) {
        ONION_LOG("CREATE: unexpected reply cmd=0x%02x", rsp.command);
        return false;
    }
    if (!hs.finish(rsp.payload, rsp.payload + HANDSHAKE_PUB_SIZE, keys_[0])) {
        ONION_LOG("CREATE: handshake MAC mismatch");
        return false;
    }

    id_      = req.circuitId;
    path_[0] = first;
    hops_    = 1;
    ONION_LOG("CREATE -> %s ok", first.name);
    return true;
}

// EXTEND: przedłużenie obwodu przez istniejące hopy.
//RELAY(EXTEND  { next.ip:port, ephPub })      zawinięte we wszystkie warstwy
//zwrotka RELAY(EXTENDED { relayEphPub, MAC })          zaszyfrowane kluczami hopów 0..n-1
bool Circuit::extend(const Relay& next) {
    if (hops_ == 0 || hops_ >= MAX_HOPS) return false;

    Handshake hs;
    if (!hs.start()) return false;

    Cell rsp;
    if (!sendRelay(RELAY_CMD_EXTEND, next.ip, next.port, hs.pub, sizeof(hs.pub), &rsp)) return false;
    if (rsp.command != CMD_RELAY || rsp.circuitId != id_) {
        ONION_LOG("EXTEND: unexpected reply cmd=0x%02x", rsp.command);
        return false;
    }

    uint8_t plain[CELL_PAYLOAD_SIZE];
    size_t  plainLen = unwrap(rsp.payload, CELL_PAYLOAD_SIZE, plain);
    if (plainLen < RELAY_HEADER_SIZE) return false;

    RelayHeader h;
    memcpy(&h, plain, sizeof(h));
    if (h.cmd != RELAY_CMD_EXTENDED || h.len < HANDSHAKE_PUB_SIZE + HMAC_SIZE ||
        RELAY_HEADER_SIZE + h.len > plainLen) {
        ONION_LOG("EXTEND: bad reply cmd=0x%02x len=%u", h.cmd, (unsigned)h.len);
        return false;
    }

    const uint8_t* relayPub = plain + RELAY_HEADER_SIZE;
    if (!hs.finish(relayPub, relayPub + HANDSHAKE_PUB_SIZE, keys_[hops_])) {
        ONION_LOG("EXTEND: handshake MAC mismatch");
        return false;
    }

    path_[hops_++] = next;
    ONION_LOG("EXTEND -> %s ok, hops=%u", next.name, (unsigned)hops_);
    return true;
}

//Dane

bool Circuit::send(uint32_t ip, uint16_t port, const uint8_t* data, size_t len) {
    if (!ready()) return false;
    return sendRelay(RELAY_CMD_DATA, ip, port, data, len, nullptr);
}

//Cebula

size_t Circuit::wrapOnion(uint8_t cmd, uint32_t ip, uint16_t port,
                          const uint8_t* payload, size_t len, uint8_t* out) const {
    if (hops_ == 0 || len > maxPayload(hops_)) return 0;

    uint8_t layer[CELL_PAYLOAD_SIZE];
    size_t  n      = packLayer(layer, ip, port, cmd, payload, len);
    size_t  outLen = aesEncrypt(layer, n, keys_[hops_ - 1], out);

    for (int i = hops_ - 2; i >= 0; i--) {
        n      = packLayer(layer, path_[i + 1].ip, path_[i + 1].port, RELAY_CMD_DATA, out, outLen);
        outLen = aesEncrypt(layer, n, keys_[i], out);
    }
    return outLen;
}

bool Circuit::sendRelay(uint8_t cmd, uint32_t ip, uint16_t port,
                        const uint8_t* payload, size_t len, Cell* reply) const {
    uint8_t onion[CELL_PAYLOAD_SIZE];
    size_t  n = wrapOnion(cmd, ip, port, payload, len, onion);
    if (n == 0) return false;

    Cell cell;
    makeCell(cell, id_, CMD_RELAY, onion, n);
    return exchangeCell(path_[0], cell, reply);
}

size_t Circuit::unwrap(const uint8_t* in, size_t len, uint8_t* out) const {
    uint8_t buf[2][CELL_PAYLOAD_SIZE];
    memcpy(buf[0], in, len);

    int cur = 0;
    for (uint8_t i = 0; i < hops_; i++) {
        len = aesDecrypt(buf[cur], len, keys_[i], buf[1 - cur]);
        cur = 1 - cur;
    }
    memcpy(out, buf[cur], len);
    return len;
}

}  // namespace onion
