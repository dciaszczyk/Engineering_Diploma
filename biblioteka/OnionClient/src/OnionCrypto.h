// Kryptografia: AES-256-CTR oraz handshake X25519 pojedynczego hopa.
#pragma once
#include "OnionProtocol.h"

namespace onion {

// AES-256-CTR. Format szyfrogramu: IV(16) || dane.
// Zwracają długość wyniku (0 przy deszyfrowaniu zbyt krótkich danych).
size_t aesEncrypt(const uint8_t* in, size_t len, const uint8_t* key, uint8_t* out);
size_t aesDecrypt(const uint8_t* in, size_t len, const uint8_t* key, uint8_t* out);

// krótkotrwały handshake jednego hopa; wspólny dla CREATE i EXTEND:
//   start()  -> wylosuj parę kluczy, `pub` wysyłasz do relaya
//   finish() -> z odpowiedzi relaya (jego pub + MAC) wylicz klucz hopa i zweryfikuj MAC
struct Handshake {
    uint8_t priv[32];
    uint8_t pub[HANDSHAKE_PUB_SIZE];

    bool start();
    bool finish(const uint8_t* relayPub, const uint8_t* mac, uint8_t* key) const;
};

}  // namespace onion
