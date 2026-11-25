// Kryptografia: prymitywy (X25519, HKDF, HMAC, AES-GCM), warstwy, handshake hopa.
// Wszystkie funkcje zwracają false przy błędzie (także przy braku entropii, patrz OnionRandom.h).
#pragma once
#include "OnionProtocol.h"

namespace onion {

// ---- Prymitywy -------------------------------------------------------------

// Losuje parę kluczy X25519 (priv: 32 B, pub: 32 B).
bool generateKeypair(uint8_t* priv, uint8_t* pub);

// Wspólny sekret X25519 (32 B). false także dla wyniku zerowego (punkt o małym rzędzie).
bool dh(const uint8_t* priv, const uint8_t* peerPub, uint8_t* out);

// HKDF-SHA256 bez soli: z `ikm` wyprowadza `outLen` bajtów, `info` oddziela konteksty użycia.
bool hkdf(const uint8_t* ikm, size_t ikmLen, const uint8_t* info, size_t infoLen,
          uint8_t* out, size_t outLen);

bool hmacSha256(const uint8_t* key, size_t keyLen, const uint8_t* data, size_t len, uint8_t* out);

// AES-256-GCM z podanym nonce (12 B); `len` to zawsze długość danych bez tagu. aad może być nullptr.
//   aeadSeal: in = dane(len),                 out = szyfrogram(len) | tag(16)
//   aeadOpen: in = szyfrogram(len) | tag(16), out = dane(len); false, gdy tag się nie zgadza
bool aeadSeal(const uint8_t* key, const uint8_t* nonce, const uint8_t* aad, size_t aadLen,
              const uint8_t* in, size_t len, uint8_t* out);
bool aeadOpen(const uint8_t* key, const uint8_t* nonce, const uint8_t* aad, size_t aadLen,
              const uint8_t* in, size_t len, uint8_t* out);

// Porównanie w stałym czasie (do MAC-ów i tagów).
bool equalConstantTime(const uint8_t* a, const uint8_t* b, size_t n);

// ---- Warstwy ---------------------------------------------------------------

// Szyfruje `plain` (len B) kluczem hopa: out = nonce(12) | szyfrogram | tag(16), czyli len + 28 B.
// `dir` (DIR_FORWARD / DIR_BACKWARD) idzie do AAD, więc warstwy nie da się odbić w drugą stronę.
bool encryptLayer(const uint8_t* key, uint8_t dir, const uint8_t* plain, size_t len, uint8_t* out);

// Odwrotność encryptLayer: `blob` ma len >= 28 B, wynik ma len - 28 B.
// false = warstwa została zmieniona albo ma zły klucz/kierunek.
bool decryptLayer(const uint8_t* key, uint8_t dir, const uint8_t* blob, size_t len, uint8_t* out);

// ---- Handshake hopa --------------------------------------------------------
//
//   klucz = HKDF( X25519(e,R) || X25519(e,S), info = "onion-hop" || wersja )
//   MAC   = HMAC( klucz, E || R || S )       E, R: efemeryczne klienta i relaya; S: statyczny relaya
//
// Klient: start() -> wysyła `pub` (E); finish() -> z odpowiedzi (R, MAC) i S z katalogu liczy klucz
//         i weryfikuje MAC (false = odpowiada ktoś bez klucza prywatnego S albo inna wersja).
// Relay:  respond() -> z E klienta i swojej pary statycznej liczy R, MAC i klucz hopa.
struct Handshake {
    uint8_t priv[32];
    uint8_t pub[PUB_SIZE];

    bool start() { return generateKeypair(priv, pub); }
    bool finish(uint8_t version, const uint8_t* relayStaticPub, const uint8_t* relayPub,
                const uint8_t* mac, uint8_t* key) const;

    static bool respond(uint8_t version, const uint8_t* clientPub, const uint8_t* staticPriv,
                        const uint8_t* staticPub, uint8_t* outPub, uint8_t* outMac, uint8_t* key);
};

}  // namespace onion
