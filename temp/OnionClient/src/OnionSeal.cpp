#include "OnionSeal.h"
#include "OnionCrypto.h"

namespace onion {
namespace {

// okm = HKDF(ss, "onion-e2e" || wersja || E || D) -> klucze i nonce'y żądania oraz odpowiedzi.
bool deriveKeys(const uint8_t* ss, const uint8_t* E, const uint8_t* D, E2eKeys* k) {
    uint8_t info[10 + 2 * PUB_SIZE];
    memcpy(info, "onion-e2e", 9);
    info[9] = PROTO_VERSION;
    memcpy(info + 10, E, PUB_SIZE);
    memcpy(info + 10 + PUB_SIZE, D, PUB_SIZE);

    uint8_t okm[88];
    if (!hkdf(ss, 32, info, sizeof(info), okm, sizeof(okm))) return false;
    memcpy(k->reqKey, okm, 32);       memcpy(k->reqNonce, okm + 32, 12);
    memcpy(k->respKey, okm + 44, 32); memcpy(k->respNonce, okm + 76, 12);
    return true;
}

}  // namespace

bool sealRequest(const uint8_t* destPub, const uint8_t* data, size_t len, uint8_t* out, E2eKeys* keys) {
    uint8_t ePriv[32], E[PUB_SIZE], ss[32];
    if (!generateKeypair(ePriv, E) || !dh(ePriv, destPub, ss)) return false;
    if (!deriveKeys(ss, E, destPub, keys)) return false;

    memcpy(out, E, PUB_SIZE);
    return aeadSeal(keys->reqKey, keys->reqNonce, nullptr, 0, data, len, out + PUB_SIZE);
}

bool openResponse(const E2eKeys& keys, const uint8_t* in, size_t len, uint8_t* out) {
    if (len < E2E_RESPONSE_OVERHEAD) return false;
    return aeadOpen(keys.respKey, keys.respNonce, nullptr, 0, in, len - TAG_SIZE, out);
}

bool openRequest(const uint8_t* destPriv, const uint8_t* destPub, const uint8_t* in, size_t len,
                 uint8_t* out, E2eKeys* keys) {
    if (len < E2E_REQUEST_OVERHEAD) return false;
    uint8_t ss[32];
    if (!dh(destPriv, in, ss) || !deriveKeys(ss, in, destPub, keys)) return false;
    return aeadOpen(keys->reqKey, keys->reqNonce, nullptr, 0, in + PUB_SIZE, len - E2E_REQUEST_OVERHEAD, out);
}

bool sealResponse(const E2eKeys& keys, const uint8_t* data, size_t len, uint8_t* out) {
    return aeadSeal(keys.respKey, keys.respNonce, nullptr, 0, data, len, out);
}

}  // namespace onion
