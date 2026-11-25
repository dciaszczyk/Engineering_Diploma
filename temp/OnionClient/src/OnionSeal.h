// Szyfrowanie end-to-end klient <-> cel (jak "sealed box"): relaye i exit widzą tylko szyfrogram.
//
// Klient zna statyczny klucz publiczny celu D (z katalogu, kind "service"):
//   ss  = X25519(e, D),  okm = HKDF(ss, info = "onion-e2e" || wersja || E || D)  (88 B)
//   żądanie   = E | AES-GCM(klucz żądania, nonce żądania, dane) | tag      (dane + 48 B)
//   odpowiedź =     AES-GCM(klucz odp.,    nonce odp.,    dane) | tag      (dane + 16 B)
// Nonce'y wynikają z HKDF, a każde żądanie ma świeże `e`, więc nie powtarzają się. Cel odpowiada
// na jedno żądanie jedną odpowiedzią. Po stronie celu służą openRequest / sealResponse.
#pragma once
#include "OnionProtocol.h"

namespace onion {

constexpr size_t E2E_REQUEST_OVERHEAD  = PUB_SIZE + TAG_SIZE;   // 48 B
constexpr size_t E2E_RESPONSE_OVERHEAD = TAG_SIZE;              // 16 B

// Klucze jednej wymiany żądanie/odpowiedź.
struct E2eKeys {
    uint8_t reqKey[32], reqNonce[12];
    uint8_t respKey[32], respNonce[12];
};

// Klient: szyfruje `data` (len B) dla celu o kluczu destPub. out ma len + 48 B.
bool sealRequest(const uint8_t* destPub, const uint8_t* data, size_t len, uint8_t* out, E2eKeys* keys);

// Klient: odszyfrowuje odpowiedź celu (len >= 16 B); wynik ma len - 16 B. false = podróbka.
bool openResponse(const E2eKeys& keys, const uint8_t* in, size_t len, uint8_t* out);

// Cel: odszyfrowuje żądanie (len >= 48 B); wynik ma len - 48 B. destPriv/destPub to para celu.
bool openRequest(const uint8_t* destPriv, const uint8_t* destPub, const uint8_t* in, size_t len,
                 uint8_t* out, E2eKeys* keys);

// Cel: szyfruje odpowiedź (len B); out ma len + 16 B.
bool sealResponse(const E2eKeys& keys, const uint8_t* data, size_t len, uint8_t* out);

}  // namespace onion
