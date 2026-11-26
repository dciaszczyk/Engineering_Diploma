// Wewnętrzne helpery komórek i tekstu końcowego, wspólne dla klienta (OnionCircuit) i relaya.
#pragma once
#include "OnionProtocol.h"
#include "OnionRandom.h"

namespace onion {

// Odczyt/zapis liczb little-endian (format protokołu), niezależnie od wyrównania.
inline void     putLE16(uint8_t* p, uint16_t v) { p[0] = v; p[1] = v >> 8; }
inline void     putLE32(uint8_t* p, uint32_t v) { p[0] = v; p[1] = v >> 8; p[2] = v >> 16; p[3] = v >> 24; }
inline uint16_t getLE16(const uint8_t* p)       { return (uint16_t)(p[0] | (p[1] << 8)); }
inline uint32_t getLE32(const uint8_t* p)       { return p[0] | (p[1] << 8) | (p[2] << 16) | ((uint32_t)p[3] << 24); }

// Składa komórkę; resztę payloadu wypełnia losowymi bajtami (przy braku entropii zerami)

inline void makeCell(Cell& cell, uint32_t id, uint8_t cmd, const uint8_t* payload, size_t len) {
    cell.circuitId = id;
    cell.command   = cmd;
    if (len) memcpy(cell.payload, payload, len);
    if (!randomBytes(cell.payload + len, CELL_PAYLOAD_SIZE - len))
        memset(cell.payload + len, 0, CELL_PAYLOAD_SIZE - len);
}

// Tekst końcowy EXTEND (size B, dopełniony zerami): T_EXTEND | ip | port | wersja | E.
inline void buildExtend(uint8_t* out, size_t size, uint32_t ip, uint16_t port, uint8_t version,
                        const uint8_t* E) {
    memset(out, 0, size);
    out[0] = T_EXTEND;
    putLE32(out + 1, ip);
    putLE16(out + 5, port);
    out[7] = version;
    memcpy(out + 8, E, PUB_SIZE);
}

// Tekst końcowy DATA (size B, dopełniony zerami): T_DATA | ip | port | długość | dane.
inline void buildData(uint8_t* out, size_t size, uint32_t ip, uint16_t port, const uint8_t* data, size_t len) {
    memset(out, 0, size);
    out[0] = T_DATA;
    putLE32(out + 1, ip);
    putLE16(out + 5, port);
    putLE16(out + 7, (uint16_t)len);
    memcpy(out + DATA_HEADER_SIZE, data, len);
}

// Tekst końcowy DATA_REPLY (size B, dopełniony zerami): T_DATA_REPLY | status | nonce | długość | odpowiedź.
inline void buildReply(uint8_t* out, size_t size, uint8_t status, const uint8_t* nonce,
                       const uint8_t* resp, size_t len) {
    memset(out, 0, size);
    out[0] = T_DATA_REPLY;
    out[1] = status;
    memcpy(out + 2, nonce, NONCE_SIZE);
    putLE16(out + 2 + NONCE_SIZE, (uint16_t)len);
    if (len) memcpy(out + REPLY_HEADER_SIZE, resp, len);
}

}  // namespace onion
