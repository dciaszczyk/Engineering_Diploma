#include "OnionCrypto.h"

#include <mbedtls/aes.h>
#include <mbedtls/ecp.h>
#include <mbedtls/md.h>
#include <mbedtls/hkdf.h>
#include <esp_random.h>

namespace onion {
namespace {

// Losowość dla mbedTLS ze sprzętowego RNG ESP32 (przy włączonym WiFi to prawdziwy TRNG).
int hwRng(void*, unsigned char* buf, size_t len) {
    esp_fill_random(buf, len);
    return 0;
}

bool mbedOk(const char* what, int ret) {
    if (ret != 0) ONION_LOG("%s failed: -0x%04X", what, (unsigned)-ret);
    return ret == 0;
}

// Porównanie w stałym czasie (do MAC-ów).
bool equalCT(const uint8_t* a, const uint8_t* b, size_t n) {
    uint8_t diff = 0;
    for (size_t i = 0; i < n; i++) diff |= a[i] ^ b[i];
    return diff == 0;
}

// AES-256-CTR: szyfrowanie i deszyfrowanie to ta sama operacja.
void aesCtr(const uint8_t* key, const uint8_t* iv, const uint8_t* in, size_t len, uint8_t* out) {
    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);
    mbedtls_aes_setkey_enc(&ctx, key, 256);

    size_t  offset = 0;
    uint8_t counter[IV_SIZE];
    uint8_t stream[16] = {0};
    memcpy(counter, iv, IV_SIZE);
    mbedtls_aes_crypt_ctr(&ctx, len, &offset, counter, stream, in, out);

    mbedtls_aes_free(&ctx);
}

// Wspólny sekret X25519 (priv: little-endian, współrzędna X punktu wynikowego).
bool x25519Shared(const uint8_t* priv, const uint8_t* peerPub, uint8_t* out) {
    mbedtls_ecp_group grp;
    mbedtls_ecp_point peer, result;
    mbedtls_mpi       d;
    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_point_init(&peer);
    mbedtls_ecp_point_init(&result);
    mbedtls_mpi_init(&d);

    size_t olen = 0;
    int ret = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_CURVE25519);
    if (!ret) ret = mbedtls_mpi_read_binary_le(&d, priv, 32);
    if (!ret) ret = mbedtls_ecp_point_read_binary(&grp, &peer, peerPub, 32);
    if (!ret) ret = mbedtls_ecp_mul(&grp, &result, &d, &peer, hwRng, nullptr);   // rng = blinding
    if (!ret) ret = mbedtls_ecp_point_write_binary(&grp, &result, MBEDTLS_ECP_PF_UNCOMPRESSED,
                                                   &olen, out, 32);
    if (!ret && olen != 32) ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;

    mbedtls_mpi_free(&d);
    mbedtls_ecp_point_free(&peer);
    mbedtls_ecp_point_free(&result);
    mbedtls_ecp_group_free(&grp);
    return mbedOk("x25519 shared", ret);
}

}  // namespace

//AES

size_t aesEncrypt(const uint8_t* in, size_t len, const uint8_t* key, uint8_t* out) {
    esp_fill_random(out, IV_SIZE);                      // IV na początku wyjścia
    aesCtr(key, out, in, len, out + IV_SIZE);
    return IV_SIZE + len;
}

size_t aesDecrypt(const uint8_t* in, size_t len, const uint8_t* key, uint8_t* out) {
    if (len < IV_SIZE) return 0;
    aesCtr(key, in, in + IV_SIZE, len - IV_SIZE, out);
    return len - IV_SIZE;
}

//Handshake

bool Handshake::start() {
    mbedtls_ecp_keypair kp;
    mbedtls_ecp_keypair_init(&kp);

    size_t olen = 0;
    int ret = mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_CURVE25519, &kp, hwRng, nullptr);
    if (!ret) ret = mbedtls_ecp_write_key_ext(&kp, &olen, priv, 32);
    if (!ret && olen != 32) ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    if (!ret) ret = mbedtls_ecp_write_public_key(&kp, MBEDTLS_ECP_PF_UNCOMPRESSED,
                                                 &olen, pub, HANDSHAKE_PUB_SIZE);
    if (!ret && olen != HANDSHAKE_PUB_SIZE) ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;

    mbedtls_ecp_keypair_free(&kp);
    return mbedOk("x25519 keygen", ret);
}

bool Handshake::finish(const uint8_t* relayPub, const uint8_t* mac, uint8_t* key) const {
    const mbedtls_md_info_t* sha256 = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

    // klucz hopa = HKDF-SHA256(X25519(priv, relayPub), bez soli, info="onion-hop-v1")
    uint8_t shared[32];
    if (!x25519Shared(priv, relayPub, shared)) return false;

    static const uint8_t info[] = "onion-hop-v1";
    if (!mbedOk("hkdf", mbedtls_hkdf(sha256, nullptr, 0, shared, sizeof(shared),
                                     info, sizeof(info) - 1, key, KEY_SIZE))) return false;

    // MAC = HMAC-SHA256(klucz hopa, nasz_pub || pub_relaya)
    uint8_t transcript[2 * HANDSHAKE_PUB_SIZE];
    memcpy(transcript, pub, HANDSHAKE_PUB_SIZE);
    memcpy(transcript + HANDSHAKE_PUB_SIZE, relayPub, HANDSHAKE_PUB_SIZE);

    uint8_t expected[HMAC_SIZE];
    if (!mbedOk("hmac", mbedtls_md_hmac(sha256, key, KEY_SIZE, transcript, sizeof(transcript),
                                        expected))) return false;

    return equalCT(expected, mac, HMAC_SIZE);
}

}  // namespace onion
