// =====================================================================
// onion_client_extend.ino
// Onion-routing prototype – CLIENT (z mechanizmem EXTEND)
// =====================================================================
#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <Preferences.h>
#include <ArduinoJson.h>

#include <mbedtls/aes.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/ecp.h>
#include <mbedtls/md.h>
#include <mbedtls/hkdf.h>

#include <esp_random.h>

// ----------------------------- Protocol ------------------------------
#define CELL_SIZE           514
#define CELL_HEADER_SIZE    5
#define CELL_PAYLOAD_SIZE   (CELL_SIZE - CELL_HEADER_SIZE)   // 509

// Komendy komórek (poziom połączenia)
#define CMD_CREATE          0x01
#define CMD_CREATED         0x02
#define CMD_RELAY           0x03
#define CMD_DESTROY         0x04

// Komendy wewnątrz RELAY (payload po odszyfrowaniu)
#define RELAY_CMD_EXTEND    0x10
#define RELAY_CMD_EXTENDED  0x11
#define RELAY_CMD_DATA      0x12

#define IV_SIZE             16
#define KEY_SIZE            32
#define HANDSHAKE_PUB_SIZE  32
#define HMAC_SIZE           32

// Nagłówek wewnętrznego RELAY (po odszyfrowaniu)
// targetIP(4) | targetPort(2) | relayCmd(1) | payloadLen(2) | payload...
#define RELAY_HEADER_SIZE   9

// Maksymalny rozmiar danych wewnątrz RELAY
#define RELAY_MAX_INNER     (CELL_PAYLOAD_SIZE - IV_SIZE - RELAY_HEADER_SIZE)  // 484

// ----------------------------- WiFi ----------------------------------
const char* SSID     = "iprivate-4";
const char* PASSWORD = "Tciaszczyk1980";

// ----------------------------- Structs -------------------------------
struct __attribute__((packed)) Cell {
    uint32_t circuitId;          // ID obwodu na danym łączu TLS
    uint8_t  command;
    uint8_t  payload[CELL_PAYLOAD_SIZE];
};

struct Relay {
    uint32_t ip;                 // big-endian
    uint16_t port;
    uint8_t  x25519Pub[32];      // długoterminowy klucz publiczny (z katalogu)
    char     name[16];
};

// Stan jednego hopa w obwodzie
struct CircuitHop {
    uint32_t circuitId;          // ID obwodu na łączu do tego hopa
    uint8_t  aesKey[KEY_SIZE];   // klucz AES-256-CTR dla warstwy tego hopa
    bool     active;
};

// ----------------------------- State ---------------------------------
Relay        gRelays[8];
uint8_t      gRelayCount = 0;
Preferences  gPrefs;

// Obwód: maksymalnie 8 hopów
#define MAX_HOPS 8
CircuitHop   gCircuit[MAX_HOPS];
uint8_t      gHopCount = 0;

// =====================================================================
// Utilities (bez zmian)
// =====================================================================
static inline uint32_t ipToU32(IPAddress ip) {
    return ((uint32_t)ip[0] << 24) | ((uint32_t)ip[1] << 16) |
           ((uint32_t)ip[2] <<  8) | ((uint32_t)ip[3]);
}
static inline IPAddress u32ToIp(uint32_t ip) {
    return IPAddress((ip >> 24) & 0xFF, (ip >> 16) & 0xFF,
                     (ip >>  8) & 0xFF,  ip        & 0xFF);
}
static void hexToBytes(const char* hex, uint8_t* out, size_t len) {
    for (size_t i = 0; i < len; i++) {
        char h[3] = { hex[2*i], hex[2*i+1], 0 };
        out[i] = (uint8_t)strtol(h, nullptr, 16);
    }
}

// =====================================================================
// AES-256-CTR (z IV na początku)
// =====================================================================
static size_t aesEncrypt(const uint8_t* data, size_t len,
                         const uint8_t* key, uint8_t* out) {
    uint8_t iv[IV_SIZE];
    esp_fill_random(iv, IV_SIZE);
    memcpy(out, iv, IV_SIZE);

    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);
    mbedtls_aes_setkey_enc(&ctx, key, 256);

    size_t nc_off = 0;
    uint8_t nonce[16], stream[16];
    memcpy(nonce, iv, 16);
    memset(stream, 0, 16);
    mbedtls_aes_crypt_ctr(&ctx, len, &nc_off, nonce, stream, data, out + IV_SIZE);

    mbedtls_aes_free(&ctx);
    return IV_SIZE + len;
}

// =====================================================================
// X25519
// =====================================================================
static bool x25519Generate(uint8_t priv[32], uint8_t pub[32]) {
    mbedtls_ecdh_context ctx;
    mbedtls_ecdh_init(&ctx);
    if (mbedtls_ecp_group_load(&ctx.grp, MBEDTLS_ECP_DP_CURVE25519) != 0) {
        mbedtls_ecdh_free(&ctx);
        return false;
    }

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context drbg;
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&drbg);
    mbedtls_ctr_drbg_seed(&drbg, mbedtls_entropy_func, &entropy, nullptr, 0);

    int ret = mbedtls_ecdh_gen_public(&ctx.grp, &ctx.d, &ctx.Q,
                                      mbedtls_ctr_drbg_random, &drbg);
    if (ret == 0) {
        mbedtls_mpi_write_binary(&ctx.d, priv, 32);
        mbedtls_mpi_write_binary(&ctx.Q.X, pub, 32);
    }

    mbedtls_ecdh_free(&ctx);
    mbedtls_ctr_drbg_free(&drbg);
    mbedtls_entropy_free(&entropy);
    return ret == 0;
}

static bool x25519Shared(const uint8_t priv[32],
                         const uint8_t peerPub[32],
                         uint8_t out[32]) {
    mbedtls_ecdh_context ctx;
    mbedtls_ecdh_init(&ctx);
    if (mbedtls_ecp_group_load(&ctx.grp, MBEDTLS_ECP_DP_CURVE25519) != 0) {
        mbedtls_ecdh_free(&ctx);
        return false;
    }

    mbedtls_mpi_read_binary(&ctx.d, priv, 32);
    if (mbedtls_ecdh_read_public(&ctx, peerPub, 32) != 0) {
        mbedtls_ecdh_free(&ctx);
        return false;
    }

    mbedtls_mpi z;
    mbedtls_mpi_init(&z);

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context drbg;
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&drbg);
    mbedtls_ctr_drbg_seed(&drbg, mbedtls_entropy_func, &entropy, nullptr, 0);

    int ret = mbedtls_ecdh_compute_shared(&ctx.grp, &z, &ctx.Qp, &ctx.d,
                                          mbedtls_ctr_drbg_random, &drbg);
    if (ret == 0) mbedtls_mpi_write_binary(&z, out, 32);

    mbedtls_mpi_free(&z);
    mbedtls_ecdh_free(&ctx);
    mbedtls_ctr_drbg_free(&drbg);
    mbedtls_entropy_free(&entropy);
    return ret == 0;
}

// =====================================================================
// HKDF / HMAC
// =====================================================================
static void hmacSHA256(const uint8_t* key, size_t keyLen,
                       const uint8_t* data, size_t dataLen,
                       uint8_t out[32]) {
    mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
                    key, keyLen, data, dataLen, out);
}

static void hkdfSHA256(const uint8_t* ikm, size_t ikmLen,
                       const uint8_t* salt, size_t saltLen,
                       const uint8_t* info, size_t infoLen,
                       uint8_t* out, size_t outLen) {
    mbedtls_hkdf(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
                 salt, saltLen, ikm, ikmLen, info, infoLen, out, outLen);
}

// =====================================================================
// Katalog relayów (NVS – bez zmian)
// =====================================================================
static void loadDefaultRelays() { /* identycznie jak w poprzedniej wersji */ }
static void loadRelaysFromNVS() { /* identycznie */ }

// =====================================================================
// TLS
// =====================================================================
static bool tlsConnect(WiFiClientSecure& c, const Relay& r) {
    c.setInsecure();
    c.setTimeout(10);
    IPAddress ip = u32ToIp(r.ip);
    if (!c.connect(ip, r.port)) {
        Serial.printf("TLS connect to %s (%s:%u) failed\n",
                      r.name, ip.toString().c_str(), r.port);
        return false;
    }
    return true;
}

static bool readExact(WiFiClientSecure& c, uint8_t* buf, size_t n,
                      uint32_t timeoutMs = 5000) {
    size_t got = 0;
    uint32_t deadline = millis() + timeoutMs;
    while (got < n) {
        if (millis() > deadline) return false;
        if (c.available()) {
            int r = c.read(buf + got, n - got);
            if (r > 0) got += r;
        } else {
            delay(5);
        }
    }
    return true;
}

// =====================================================================
// Handshake BEZPOŚREDNI (tylko dla pierwszego hopa)
// =====================================================================
static bool handshakeFirstHop(const Relay& relay, CircuitHop& out) {
    WiFiClientSecure tls;
    if (!tlsConnect(tls, relay)) return false;

    uint8_t ephPriv[32], ephPub[32];
    if (!x25519Generate(ephPriv, ephPub)) {
        tls.stop();
        return false;
    }

    // CREATE
    Cell create{};
    create.circuitId = esp_random();
    create.command   = CMD_CREATE;
    memset(create.payload, 0, CELL_PAYLOAD_SIZE);
    memcpy(create.payload, ephPub, HANDSHAKE_PUB_SIZE);
    esp_fill_random(create.payload + HANDSHAKE_PUB_SIZE,
                    CELL_PAYLOAD_SIZE - HANDSHAKE_PUB_SIZE);

    if (tls.write((uint8_t*)&create, sizeof(create)) != sizeof(create)) {
        tls.stop();
        return false;
    }

    // CREATED
    Cell created{};
    if (!readExact(tls, (uint8_t*)&created, sizeof(created))) {
        tls.stop();
        return false;
    }
    tls.stop();

    if (created.command != CMD_CREATED || created.circuitId != create.circuitId) {
        return false;
    }

    // Wyciągnięcie efemerycznego klucza publicznego relay'a
    uint8_t relayEphPub[HANDSHAKE_PUB_SIZE];
    memcpy(relayEphPub, created.payload, HANDSHAKE_PUB_SIZE);

    uint8_t shared[32];
    if (!x25519Shared(ephPriv, relayEphPub, shared)) return false;

    const uint8_t info[] = "onion-hop-v1";
    hkdfSHA256(shared, sizeof(shared), nullptr, 0,
               info, sizeof(info) - 1, out.aesKey, KEY_SIZE);

    // Weryfikacja HMAC (relay dowodzi znajomości klucza)
    uint8_t transcript[HANDSHAKE_PUB_SIZE * 2];
    memcpy(transcript, ephPub, HANDSHAKE_PUB_SIZE);
    memcpy(transcript + HANDSHAKE_PUB_SIZE, relayEphPub, HANDSHAKE_PUB_SIZE);

    uint8_t expected[HMAC_SIZE];
    hmacSHA256(out.aesKey, KEY_SIZE, transcript, sizeof(transcript), expected);

    if (memcmp(expected, created.payload + HANDSHAKE_PUB_SIZE, HMAC_SIZE) != 0) {
        return false;
    }

    out.circuitId = create.circuitId;
    out.active    = true;
    return true;
}

// =====================================================================
// EXTEND – przedłużenie obwodu przez istniejące połączenie
// =====================================================================
// Buduje komórkę RELAY z komendą EXTEND, która zostanie wysłana do
// ostatniego hopa. Payload EXTEND zawiera:
//   nextIP(4) | nextPort(2) | ephPub(32) | HMAC(32) | padding
// Całość jest szyfrowana kluczem ostatniego hopa (warstwa cebuli).
static bool sendExtendToLastHop(const Relay& nextRelay) {
    if (gHopCount == 0 || gHopCount >= MAX_HOPS) return false;

    uint8_t ephPriv[32], ephPub[32];
    if (!x25519Generate(ephPriv, ephPub)) return false;

    // --- warstwa wewnętrzna: dla ostatniego ustanowionego hopa ---
    // header(9) = targetIP(4) | targetPort(2) | relayCmd(1) | payloadLen(2)
    uint8_t inner[CELL_PAYLOAD_SIZE];
    size_t  off = 0;
    memcpy(inner + off, &nextRelay.ip,   4); off += 4;
    memcpy(inner + off, &nextRelay.port, 2); off += 2;
    inner[off++] = RELAY_CMD_EXTEND;
    uint16_t ephLen = HANDSHAKE_PUB_SIZE;
    memcpy(inner + off, &ephLen, 2); off += 2;
    memcpy(inner + off, ephPub, HANDSHAKE_PUB_SIZE); off += HANDSHAKE_PUB_SIZE;
    // off = 41

    uint8_t cipher[CELL_PAYLOAD_SIZE];
    size_t  cipherLen = aesEncrypt(inner, off,
                                   gCircuit[gHopCount - 1].aesKey, cipher);
    // cipherLen = 16 + 41 = 57

    // --- owijanie dla wcześniejszych hopów (jak w buildOnion) ---
    for (int i = gHopCount - 2; i >= 0; i--) {
        uint8_t wrapper[CELL_PAYLOAD_SIZE];
        size_t  w = 0;
        uint32_t nextIP   = gRelays[i + 1].ip;
        uint16_t nextPort = gRelays[i + 1].port;
        memcpy(wrapper + w, &nextIP,   4); w += 4;
        memcpy(wrapper + w, &nextPort, 2); w += 2;
        wrapper[w++] = RELAY_CMD_DATA;
        uint16_t innerLen = (uint16_t)cipherLen;
        memcpy(wrapper + w, &innerLen, 2); w += 2;
        memcpy(wrapper + w, cipher, cipherLen); w += cipherLen;

        cipherLen = aesEncrypt(wrapper, w, gCircuit[i].aesKey, cipher);
    }

    // --- wyślij do entry ---
    WiFiClientSecure tls;
    if (!tlsConnect(tls, gRelays[0])) return false;

    Cell cell{};
    cell.circuitId = gCircuit[0].circuitId;
    cell.command   = CMD_RELAY;
    memcpy(cell.payload, cipher, cipherLen);
    if (cipherLen < CELL_PAYLOAD_SIZE)
        esp_fill_random(cell.payload + cipherLen, CELL_PAYLOAD_SIZE - cipherLen);

    if (tls.write((uint8_t*)&cell, sizeof(cell)) != sizeof(cell)) {
        tls.stop(); return false;
    }

    Cell extended{};
    if (!readExact(tls, (uint8_t*)&extended, sizeof(extended))) {
        tls.stop(); return false;
    }
    tls.stop();

    if (extended.command != CMD_RELAY ||
        extended.circuitId != gCircuit[0].circuitId) return false;

    // --- odszyfruj K1, K2, …, K_last (kolejność: od entry do ostatniego hopa) ---
    uint8_t buf[CELL_PAYLOAD_SIZE];
    size_t  bufLen = CELL_PAYLOAD_SIZE;
    memcpy(buf, extended.payload, CELL_PAYLOAD_SIZE);
    for (int i = 0; i < gHopCount; i++) {
        uint8_t tmp[CELL_PAYLOAD_SIZE];
        size_t  n = aesDecrypt(buf, bufLen, gCircuit[i].aesKey, tmp);
        memcpy(buf, tmp, n);
        bufLen = n;
    }
    if (bufLen < RELAY_HEADER_SIZE) return false;

    uint8_t  relayCmd  = buf[6];
    uint16_t payloadLen;
    memcpy(&payloadLen, buf + 7, 2);

    if (relayCmd != RELAY_CMD_EXTENDED) return false;
    if (payloadLen < HANDSHAKE_PUB_SIZE + HMAC_SIZE) return false;

    uint8_t  relayEphPub[HANDSHAKE_PUB_SIZE];
    memcpy(relayEphPub, buf + RELAY_HEADER_SIZE, HANDSHAKE_PUB_SIZE);
    const uint8_t* receivedHmac = buf + RELAY_HEADER_SIZE + HANDSHAKE_PUB_SIZE;

    // --- wylicz klucz nowego hopa ---
    uint8_t shared[32];
    if (!x25519Shared(ephPriv, relayEphPub, shared)) return false;

    uint8_t newKey[KEY_SIZE];
    const uint8_t info[] = "onion-hop-v1";
    hkdfSHA256(shared, sizeof(shared), nullptr, 0,
               info, sizeof(info) - 1, newKey, KEY_SIZE);

    // --- weryfikacja HMAC od nowego hopa ---
    uint8_t transcript[HANDSHAKE_PUB_SIZE * 2];
    memcpy(transcript, ephPub, HANDSHAKE_PUB_SIZE);
    memcpy(transcript + HANDSHAKE_PUB_SIZE, relayEphPub, HANDSHAKE_PUB_SIZE);
    uint8_t expected[HMAC_SIZE];
    hmacSHA256(newKey, KEY_SIZE, transcript, sizeof(transcript), expected);

    if (memcmp(expected, receivedHmac, HMAC_SIZE) != 0) {
        Serial.println("EXTENDED HMAC mismatch");
        return false;
    }

    gCircuit[gHopCount].circuitId = 0; // nie używamy na drucie
    memcpy(gCircuit[gHopCount].aesKey, newKey, KEY_SIZE);
    gCircuit[gHopCount].active = true;
    gHopCount++;

    Serial.printf("EXTEND -> %s ok, hops=%u\n", nextRelay.name, gHopCount);
    return true;
}

// =====================================================================
// Budowa cebuli (z uwzględnieniem wielu hopów)
// =====================================================================
// Buduje cebulę dla docelowego adresu, używając kluczy wszystkich
// aktywnych hopów w gCircuit. Wynik to jedna warstwa zewnętrzna,
// gotowa do wysłania do entry relay jako RELAY.
static size_t buildOnion(uint32_t finalIP, uint16_t finalPort,
                         const uint8_t* data, size_t dataLen,
                         uint8_t* outCipher) {
    if (gHopCount == 0 || dataLen > RELAY_MAX_INNER) return 0;

    // Najgłębsza warstwa – dla ostatniego hopa
    uint8_t inner[CELL_PAYLOAD_SIZE];
    size_t  off = 0;
    memcpy(inner + off, &finalIP,   4); off += 4;
    memcpy(inner + off, &finalPort, 2); off += 2;
    inner[off++] = RELAY_CMD_DATA;
    uint16_t len16 = (uint16_t)dataLen;
    memcpy(inner + off, &len16, 2); off += 2;
    memcpy(inner + off, data, dataLen); off += dataLen;

    uint8_t cipher[CELL_PAYLOAD_SIZE];
    size_t  cipherLen = aesEncrypt(inner, off,
                                   gCircuit[gHopCount - 1].aesKey,
                                   cipher);

    // Zawijanie od przedostatniego hopa w górę
    for (int i = gHopCount - 2; i >= 0; i--) {
        uint8_t wrapper[CELL_PAYLOAD_SIZE];
        size_t  w = 0;

        // Adres następnego hopa (dla przekierowania)
        uint32_t nextIP   = gRelays[i + 1].ip;
        uint16_t nextPort = gRelays[i + 1].port;
        memcpy(wrapper + w, &nextIP,   4); w += 4;
        memcpy(wrapper + w, &nextPort, 2); w += 2;
        wrapper[w++] = RELAY_CMD_DATA; // nie jest to finalny cel, tylko przekazanie
        uint16_t innerLen = (uint16_t)cipherLen;
        memcpy(wrapper + w, &innerLen, 2); w += 2;
        memcpy(wrapper + w, cipher, cipherLen); w += cipherLen;

        cipherLen = aesEncrypt(wrapper, w, gCircuit[i].aesKey, cipher);
    }

    memcpy(outCipher, cipher, cipherLen);
    return cipherLen;
}

// =====================================================================
// Wysłanie komórki RELAY do entry relay
// =====================================================================
static bool sendRelayCell(const uint8_t* cipherPayload, size_t cipherLen) {
    if (gHopCount == 0 || cipherLen > CELL_PAYLOAD_SIZE) return false;

    const Relay& entry = gRelays[0];
    WiFiClientSecure tls;
    if (!tlsConnect(tls, entry)) return false;

    Cell cell{};
    cell.circuitId = gCircuit[0].circuitId;
    cell.command   = CMD_RELAY;
    memcpy(cell.payload, cipherPayload, cipherLen);
    if (cipherLen < CELL_PAYLOAD_SIZE) {
        esp_fill_random(cell.payload + cipherLen,
                        CELL_PAYLOAD_SIZE - cipherLen);
    }

    bool ok = tls.write((uint8_t*)&cell, sizeof(cell)) == sizeof(cell);
    tls.stop();
    return ok;
}

// =====================================================================
// Główna procedura: zbuduj obwód 3-hopowy i wyślij dane
// =====================================================================
static void runOnionDemo() {
    if (gRelayCount < 3) {
        Serial.println("Need at least 3 relays");
        return;
    }

    // Reset stanu obwodu
    gHopCount = 0;
    memset(gCircuit, 0, sizeof(gCircuit));

    // ---- Hop 1: bezpośredni handshake ----
    Serial.printf("Creating first hop with %s...\n", gRelays[0].name);
    if (!handshakeFirstHop(gRelays[0], gCircuit[0])) {
        Serial.println("First-hop handshake failed");
        return;
    }
    gHopCount = 1;

    // ---- Hop 2: EXTEND ----
    Serial.printf("Extending to %s...\n", gRelays[1].name);
    if (!sendExtendToLastHop(gRelays[1])) {
        Serial.println("EXTEND to hop 2 failed");
        return;
    }

    // ---- Hop 3: EXTEND ----
    Serial.printf("Extending to %s...\n", gRelays[2].name);
    if (!sendExtendToLastHop(gRelays[2])) {
        Serial.println("EXTEND to hop 3 failed");
        return;
    }

    Serial.printf("Circuit established with %u hops\n", gHopCount);

    // ---- Wyślij dane przez gotowy obwód ----
    const uint32_t DEST_IP   = 0xAC1066F3;   // 172.16.102.243
    const uint16_t DEST_PORT = 9000;
    const char*    text      = "hello world";

    uint8_t onion[CELL_PAYLOAD_SIZE];
    size_t  onionLen = buildOnion(DEST_IP, DEST_PORT,
                                  (const uint8_t*)text, strlen(text),
                                  onion);
    if (onionLen == 0) {
        Serial.println("buildOnion failed");
        return;
    }

    if (sendRelayCell(onion, onionLen)) {
        Serial.println("Data cell sent through circuit");
    } else {
        Serial.println("Failed to send data cell");
    }
}

// =====================================================================
// setup / loop
// =====================================================================
void setup() {
    Serial.begin(115200);
    delay(200);

    loadRelaysFromNVS();
    Serial.printf("Loaded %u relays\n", gRelayCount);

    connectWiFi();

    uint8_t dummy[32];
    esp_fill_random(dummy, sizeof(dummy)); // rozgrzanie entropii
}

void loop() {
    runOnionDemo();
    delay(15000);
}