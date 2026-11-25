#include "OnionCrypto.h"
#include "OnionRandom.h"

#include <mbedtls/ecp.h>
#include <mbedtls/gcm.h>
#include <mbedtls/hkdf.h>
#include <mbedtls/md.h>

namespace onion {
namespace {

constexpr int ERR_ENTROPY = -0x003C;   // MBEDTLS_ERR_ENTROPY_SOURCE_FAILED

// Losowość dla mbedTLS przez onion::randomBytes (TRNG z fallbackiem, patrz OnionRandom.h).
int hwRng(void*, unsigned char* buf, size_t len) {
    return randomBytes(buf, len) ? 0 : ERR_ENTROPY;
}

// Loguje błąd mbedTLS i zamienia kod na bool.
bool mbedOk(const char* what, int ret) {
    if (ret != 0) ONION_LOG("%s failed: -0x%04X", what, (unsigned)-ret);
    return ret == 0;
}

bool isZero(const uint8_t* a, size_t n) {
    uint8_t acc = 0;
    for (size_t i = 0; i < n; i++) acc |= a[i];
    return acc == 0;
}

const mbedtls_md_info_t* sha256() {
    return mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
}

// Info HKDF handshake'u: "onion-hop" + numer wersji.
size_t hopInfo(uint8_t version, uint8_t* out) {
    memcpy(out, "onion-hop", 9);
    out[9] = version;
    return 10;
}

}  // namespace

// ---- Prymitywy -------------------------------------------------------------

bool generateKeypair(uint8_t* priv, uint8_t* pub) {
    mbedtls_ecp_keypair kp;
    mbedtls_ecp_keypair_init(&kp);

    size_t olen = 0;
    int ret = mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_CURVE25519, &kp, hwRng, nullptr);
    if (!ret) ret = mbedtls_ecp_write_key_ext(&kp, &olen, priv, 32);
    if (!ret && olen != 32) ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    if (!ret) ret = mbedtls_ecp_write_public_key(&kp, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, pub, PUB_SIZE);
    if (!ret && olen != PUB_SIZE) ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;

    mbedtls_ecp_keypair_free(&kp);
    return mbedOk("x25519 keygen", ret);
}

bool dh(const uint8_t* priv, const uint8_t* peerPub, uint8_t* out) {
    mbedtls_ecp_group grp;
    mbedtls_ecp_point peer, result;
    mbedtls_mpi       d;
    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_point_init(&peer);
    mbedtls_ecp_point_init(&result);
    mbedtls_mpi_init(&d);

    size_t olen = 0;
    int ret = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_CURVE25519);
    if (!ret) ret = mbedtls_mpi_read_binary_le(&d, priv, 32);                    // klucz prywatny: little-endian
    if (!ret) ret = mbedtls_ecp_point_read_binary(&grp, &peer, peerPub, 32);
    if (!ret) ret = mbedtls_ecp_mul(&grp, &result, &d, &peer, hwRng, nullptr);   // rng = blinding
    if (!ret) ret = mbedtls_ecp_point_write_binary(&grp, &result, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, out, 32);
    if (!ret && olen != 32) ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    if (!ret && isZero(out, 32)) ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;           // punkt niskiego rzędu

    mbedtls_mpi_free(&d);
    mbedtls_ecp_point_free(&peer);
    mbedtls_ecp_point_free(&result);
    mbedtls_ecp_group_free(&grp);
    return mbedOk("x25519 dh", ret);
}

bool hkdf(const uint8_t* ikm, size_t ikmLen, const uint8_t* info, size_t infoLen,
          uint8_t* out, size_t outLen) {
    return mbedOk("hkdf", mbedtls_hkdf(sha256(), nullptr, 0, ikm, ikmLen, info, infoLen, out, outLen));
}

bool hmacSha256(const uint8_t* key, size_t keyLen, const uint8_t* data, size_t len, uint8_t* out) {
    return mbedOk("hmac", mbedtls_md_hmac(sha256(), key, keyLen, data, len, out));
}

bool aeadSeal(const uint8_t* key, const uint8_t* nonce, const uint8_t* aad, size_t aadLen,
              const uint8_t* in, size_t len, uint8_t* out) {
    mbedtls_gcm_context ctx;
    mbedtls_gcm_init(&ctx);
    int ret = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, 256);
    if (!ret) ret = mbedtls_gcm_crypt_and_tag(&ctx, MBEDTLS_GCM_ENCRYPT, len, nonce, NONCE_SIZE,
                                              aad, aadLen, in, out, TAG_SIZE, out + len);
    mbedtls_gcm_free(&ctx);
    return mbedOk("gcm seal", ret);
}

bool aeadOpen(const uint8_t* key, const uint8_t* nonce, const uint8_t* aad, size_t aadLen,
              const uint8_t* in, size_t len, uint8_t* out) {
    mbedtls_gcm_context ctx;
    mbedtls_gcm_init(&ctx);
    int ret = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, 256);
    if (!ret) ret = mbedtls_gcm_auth_decrypt(&ctx, len, nonce, NONCE_SIZE, aad, aadLen,
                                             in + len, TAG_SIZE, in, out);   // tag leży za szyfrogramem
    mbedtls_gcm_free(&ctx);
    return ret == 0;   // zły tag to normalna sytuacja (podróbka), bez logu błędu
}

bool equalConstantTime(const uint8_t* a, const uint8_t* b, size_t n) {
    uint8_t diff = 0;
    for (size_t i = 0; i < n; i++) diff |= a[i] ^ b[i];
    return diff == 0;
}

// ---- Warstwy ---------------------------------------------------------------

bool encryptLayer(const uint8_t* key, uint8_t dir, const uint8_t* plain, size_t len, uint8_t* out) {
    if (!randomBytes(out, NONCE_SIZE)) return false;               // nonce na początku wyjścia
    return aeadSeal(key, out, &dir, 1, plain, len, out + NONCE_SIZE);
}

bool decryptLayer(const uint8_t* key, uint8_t dir, const uint8_t* blob, size_t len, uint8_t* out) {
    if (len < LAYER_OVERHEAD) return false;
    return aeadOpen(key, blob, &dir, 1, blob + NONCE_SIZE, len - LAYER_OVERHEAD, out);
}

// ---- Handshake -------------------------------------------------------------

// Klucz hopa z dwóch DH: ikm = DH(efemeryczny) || DH(statyczny).
static bool hopKey(uint8_t version, const uint8_t* ikm, uint8_t* key) {
    uint8_t info[10];
    return hkdf(ikm, 64, info, hopInfo(version, info), key, KEY_SIZE);
}

// MAC = HMAC(klucz hopa, E || R || S)
static bool handshakeMac(const uint8_t* key, const uint8_t* E, const uint8_t* R, const uint8_t* S,
                         uint8_t* out) {
    uint8_t transcript[3 * PUB_SIZE];
    memcpy(transcript, E, PUB_SIZE);
    memcpy(transcript + PUB_SIZE, R, PUB_SIZE);
    memcpy(transcript + 2 * PUB_SIZE, S, PUB_SIZE);
    return hmacSha256(key, KEY_SIZE, transcript, sizeof(transcript), out);
}

bool Handshake::finish(uint8_t version, const uint8_t* relayStaticPub, const uint8_t* relayPub,
                       const uint8_t* mac, uint8_t* key) const {
    uint8_t ikm[64];
    if (!dh(priv, relayPub, ikm) || !dh(priv, relayStaticPub, ikm + 32)) return false;
    if (!hopKey(version, ikm, key)) return false;

    uint8_t expected[HMAC_SIZE];
    if (!handshakeMac(key, pub, relayPub, relayStaticPub, expected)) return false;
    return equalConstantTime(expected, mac, HMAC_SIZE);
}

bool Handshake::respond(uint8_t version, const uint8_t* clientPub, const uint8_t* staticPriv,
                        const uint8_t* staticPub, uint8_t* outPub, uint8_t* outMac, uint8_t* key) {
    Handshake eph;                                       // efemeryczna para relaya (r, R)
    if (!eph.start()) return false;

    uint8_t ikm[64];
    if (!dh(eph.priv, clientPub, ikm) ||                 // X25519(r, E)
        !dh(staticPriv, clientPub, ikm + 32)) return false;   // X25519(s, E)
    if (!hopKey(version, ikm, key)) return false;
    if (!handshakeMac(key, clientPub, eph.pub, staticPub, outMac)) return false;

    memcpy(outPub, eph.pub, PUB_SIZE);
    return true;
}

}  // namespace onion
