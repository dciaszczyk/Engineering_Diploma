#include "OnionCircuit.h"
#include "OnionCell.h"
#include "OnionCrypto.h"
#include "OnionTransport.h"

namespace onion {

// ---- Budowa i niszczenie obwodu --------------------------------------------

void Circuit::reset() {
    id_   = 0;
    hops_ = 0;
    memset(keys_, 0, sizeof(keys_));
}

// DESTROY jest jawne (poziom łącza): komórka z id obwodu, bez odpowiedzi. Każdy relay usuwa
// obwód i wysyła DESTROY do następnego hopa pod jego własnym id.
void Circuit::destroy() {
    if (ready()) {
        Cell cell;
        makeCell(cell, id_, CMD_DESTROY, nullptr, 0);
        if (exchangeCell(entry_, cell)) ONION_LOG("DESTROY sent");
    }
    reset();
}

bool Circuit::build(const Relay* path, uint8_t hops) {
    reset();
    if (hops == 0 || hops > MAX_HOPS) return false;

    if (!create(path[0])) return false;
    for (uint8_t i = 1; i < hops; i++) {
        if (!extend(path[i])) { destroy(); return false; }
    }
    ONION_LOG("circuit ready, %u hops", (unsigned)hops_);
    return true;
}

// CREATE: bezpośredni handshake z entry relayem.
//   -> CREATE  { wersja, głębokość 0, E }
//   <- CREATED { R, MAC }          albo DESTROY { wersja relaya }, gdy wersje się nie zgadzają
bool Circuit::create(const Relay& first) {
    Handshake hs;
    uint32_t  cid;
    if (!hs.start() || !randomBytes(&cid, sizeof(cid))) return false;

    uint8_t body[2 + PUB_SIZE] = {PROTO_VERSION, 0};
    memcpy(body + 2, hs.pub, PUB_SIZE);

    Cell req, rsp;
    makeCell(req, cid, CMD_CREATE, body, sizeof(body));
    if (!exchangeCell(first, req, &rsp)) return false;

    if (rsp.command == CMD_DESTROY) {
        ONION_LOG("CREATE: %s speaks protocol v%u, this client v%u", first.name,
                  (unsigned)rsp.payload[0], (unsigned)PROTO_VERSION);
        return false;
    }
    if (rsp.command != CMD_CREATED || rsp.circuitId != req.circuitId) {
        ONION_LOG("CREATE: unexpected reply cmd=0x%02x", rsp.command);
        return false;
    }
    if (!hs.finish(PROTO_VERSION, first.x25519Pub, rsp.payload, rsp.payload + PUB_SIZE, keys_[0])) {
        ONION_LOG("CREATE: handshake verification failed (%s)", first.name);
        return false;
    }

    id_    = cid;
    entry_ = first;
    hops_  = 1;
    ONION_LOG("CREATE -> %s ok", first.name);
    return true;
}

// EXTEND: przedłużenie obwodu przez istniejące hopy.
//   -> RELAY(EXTEND  { next.ip:port, wersja, E })       zawinięte we wszystkie warstwy
//   <- RELAY(EXTENDED { R, MAC })                        warstwy hopów 0..n-1 w drodze powrotnej
bool Circuit::extend(const Relay& next) {
    if (hops_ == 0 || hops_ >= MAX_HOPS) return false;

    Handshake hs;
    if (!hs.start()) return false;

    uint8_t terminal[CELL_PAYLOAD_SIZE];
    buildExtend(terminal, terminalSize(hops_), next.ip, next.port, PROTO_VERSION, hs.pub);

    Cell rsp;
    if (!exchange(terminal, &rsp, 20000, nullptr)) return false;
    if (rsp.command != CMD_RELAY || rsp.circuitId != id_) {
        ONION_LOG("EXTEND: unexpected reply cmd=0x%02x", rsp.command);
        return false;
    }

    uint8_t text[CELL_PAYLOAD_SIZE];
    if (!unwrap(rsp.payload, text)) {
        ONION_LOG("EXTEND: reply authentication failed");
        return false;
    }
    if (text[0] != T_EXTENDED) {
        ONION_LOG("EXTEND: unexpected reply 0x%02x", text[0]);
        return false;
    }
    if (!hs.finish(PROTO_VERSION, next.x25519Pub, text + 1, text + 1 + PUB_SIZE, keys_[hops_])) {
        ONION_LOG("EXTEND: handshake verification failed (%s)", next.name);
        return false;
    }

    hops_++;
    ONION_LOG("EXTEND -> %s ok, hops=%u", next.name, (unsigned)hops_);
    return true;
}

// ---- Dane ------------------------------------------------------------------

SendStatus Circuit::send(uint32_t ip, uint16_t port, const uint8_t* data, size_t len,
                         Response* reply, uint32_t timeoutMs) {
    if (!ready()) return SendStatus::NoCircuit;
    if (len > maxPayload(hops_)) return SendStatus::Failed;

    uint8_t terminal[CELL_PAYLOAD_SIZE];
    buildData(terminal, terminalSize(hops_), ip, port, data, len);

    if (!reply)
        return exchange(terminal, nullptr, 0, nullptr) ? SendStatus::Sent : SendStatus::Failed;

    // Odpowiedź: DATA_REPLY { status, nonce, długość, odpowiedź celu }. Nonce to nonce najgłębszej
    // warstwy tej wiadomości, więc cudza (np. odtworzona) odpowiedź nie przejdzie.
    uint8_t nonce[NONCE_SIZE];
    Cell    rsp;
    if (!exchange(terminal, &rsp, timeoutMs, nonce)) return SendStatus::NoAck;
    if (rsp.command != CMD_RELAY || rsp.circuitId != id_) {
        ONION_LOG("DATA: unexpected reply cmd=0x%02x", rsp.command);
        return SendStatus::NoAck;
    }

    uint8_t text[CELL_PAYLOAD_SIZE];
    if (!unwrap(rsp.payload, text)) {
        ONION_LOG("DATA: reply authentication failed");
        return SendStatus::Mismatch;
    }
    if (text[0] != T_DATA_REPLY || memcmp(text + 2, nonce, NONCE_SIZE) != 0) {
        ONION_LOG("DATA: reply does not belong to this message");
        return SendStatus::Mismatch;
    }

    size_t n = getLE16(text + 2 + NONCE_SIZE);
    if (n > maxResponse(hops_)) return SendStatus::Mismatch;
    reply->len = n < reply->cap ? n : reply->cap;
    memcpy(reply->buf, text + REPLY_HEADER_SIZE, reply->len);
    return text[1] == STATUS_OK ? SendStatus::Delivered : SendStatus::ExitFailed;
}

// ---- Warstwy ---------------------------------------------------------------

bool Circuit::wrap(const uint8_t* terminal, uint8_t* out, uint8_t* innerNonce) const {
    uint8_t bufA[CELL_PAYLOAD_SIZE], bufB[CELL_PAYLOAD_SIZE];
    uint8_t *cur = bufA, *next = bufB;

    size_t n = terminalSize(hops_);
    if (!encryptLayer(keys_[hops_ - 1], DIR_FORWARD, terminal, n, cur)) return false;   // dla ostatniego hopa
    n += LAYER_OVERHEAD;
    if (innerNonce) memcpy(innerNonce, cur, NONCE_SIZE);

    for (int i = hops_ - 2; i >= 0; i--) {                                              // reszta hopów do entry
        if (!encryptLayer(keys_[i], DIR_FORWARD, cur, n, next)) return false;
        n += LAYER_OVERHEAD;
        uint8_t* t = cur; cur = next; next = t;
    }
    if (n != CELL_PAYLOAD_SIZE) return false;
    memcpy(out, cur, n);
    return true;
}

bool Circuit::unwrap(const uint8_t* payload, uint8_t* terminalOut) const {
    uint8_t bufA[CELL_PAYLOAD_SIZE], bufB[CELL_PAYLOAD_SIZE];
    memcpy(bufA, payload, CELL_PAYLOAD_SIZE);
    uint8_t *cur = bufA, *next = bufB;

    size_t n = CELL_PAYLOAD_SIZE;                                  // warstwa entry = cały payload
    for (uint8_t i = 0; i < hops_; i++) {
        if (!decryptLayer(keys_[i], DIR_BACKWARD, cur, n, next)) return false;
        n -= LAYER_OVERHEAD;
        uint8_t* t = cur; cur = next; next = t;
    }
    memcpy(terminalOut, cur, n);                                   // n == terminalSize(hops_)
    return true;
}

bool Circuit::exchange(const uint8_t* terminal, Cell* reply, uint32_t timeoutMs, uint8_t* innerNonce) const {
    uint8_t payload[CELL_PAYLOAD_SIZE];
    if (!wrap(terminal, payload, innerNonce)) return false;

    Cell cell;
    makeCell(cell, id_, CMD_RELAY, payload, CELL_PAYLOAD_SIZE);
    return exchangeCell(entry_, cell, reply, timeoutMs);
}

}  // namespace onion
