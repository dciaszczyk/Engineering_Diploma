#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <Preferences.h>
#include <ArduinoJson.h>

#include <mbedtls/aes.h>
#include <mbedtls/gcm.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/ecp.h>
#include <mbedtls/md.h>
#include <mbedtls/hkdf.h>

#include <esp_random.h>

//format pakietu

#define CELL_SIZE           514 //taki jak tor
#define CELL_HEADER_SIZE    5
#define CELL_PAYLOAD_SIZE   (CELL_SIZE - CELL_HEADER_SIZE)   //509

//Polecenia dla komórek (plain)

#define CMD_CREATE          0x01 //tworzenie obwodu
#define CMD_CREATED         0x02 //odpowiedź
#define CMD_RELAY           0x03 //przekaż
#define CMD_DESTROY         0x04 //rozwiązanie obwodu

//Polecenia dla relayi (po odszyfrowaniu)

#define RELAY_CMD_EXTEND    0x10 //dodaj kolejny relay do obwodu
#define RELAY_CMD_EXTENDED  0x11 //zwrotka
#define RELAY_CMD_DATA      0x12 //przekaż

//rozmiary kryptograficzne

#define IV_SIZE             16
#define KEY_SIZE            32
#define HANDSHAKE_PUB_SIZE  32
#define HMAC_SIZE           32
#define GCM_NONCE_SIZE 12
#define GCM_TAG_SIZE   16

//Nagłówek wewnętrzny dla relay
//targetIP(4), targetPort(2), relayCmd(1), payloadLen(2), payload, padding

#define RELAY_HEADER_SIZE   9

// Maksymalny rozmiar danych wewnątrz RELAY

#define RELAY_MAX_INNER     (CELL_PAYLOAD_SIZE - IV_SIZE - RELAY_HEADER_SIZE)  //484

//WiFi

const char* SSID     = "iprivate-4";
const char* PASSWORD = "Tciaszczyk1980";

//Structy

struct __attribute__((packed)) Cell { //__attribute__((packed)) powstrzymuje padding przez kompilator
    uint32_t circuitId;
    uint8_t  command;
    uint8_t  payload[CELL_PAYLOAD_SIZE];
};

struct Relay {
    uint32_t ip;
    uint16_t port;
    uint8_t  x25519Pub[32]; //klucz publiczny
    char     name[16];
};

// Stan jednego hopa w obwodzie

struct CircuitHop {
    uint32_t circuitId;          
    uint8_t  aesKey[KEY_SIZE];
    bool     active;
};

//Stan

Relay        gRelays[8];
uint8_t      gRelayCount = 0;
Preferences  gPrefs;

#define MAX_HOPS 3
CircuitHop   gCircuit[MAX_HOPS];
uint8_t      gHopCount = 0;

static inline uint32_t ipToU32(IPAddress ip) {
    return ((uint32_t)ip[0] << 24) | ((uint32_t)ip[1] << 16) |
           ((uint32_t)ip[2] << 8) | ((uint32_t)ip[3]);
}

static inline IPAddress u32ToIp(uint32_t ip) {
    return IPAddress((ip >> 24) & 0xFF, (ip >> 16) & 0xFF,
                     (ip >> 8) & 0xFF,  ip & 0xFF);
}

static void hexToBytes(const char* hex, uint8_t* out, size_t len) {
    for (size_t i = 0; i < len; i++) {
        char h[3] = { hex[2*i], hex[2*i+1], 0 };
        out[i] = (uint8_t)strtol(h, nullptr, 16);
    }
}

//szyfrowanie aes w trybie counter

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

static size_t aesDecrypt(const uint8_t* data, size_t len,
                         const uint8_t* key, uint8_t* out) {
    if (len < IV_SIZE) return 0;

    uint8_t iv[IV_SIZE];
    memcpy(iv, data, IV_SIZE);
    size_t cipherLen = len - IV_SIZE;

    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);
    mbedtls_aes_setkey_enc(&ctx, key, 256);   // tryb CTR używa szyfrowania do deszyfrowania

    size_t nc_off = 0;
    uint8_t nonce[16], stream[16];
    memcpy(nonce, iv, 16);
    memset(stream, 0, 16);
    mbedtls_aes_crypt_ctr(&ctx, cipherLen, &nc_off, nonce, stream,
                          data + IV_SIZE, out);

    mbedtls_aes_free(&ctx);
    return cipherLen;
}

static const char* mbedtlsErrName(int ret) {
    switch (ret) {
        case 0:                          return "OK";
        case MBEDTLS_ERR_ECP_BAD_INPUT_DATA:      return "ECP_BAD_INPUT_DATA";
        case MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE: return "ECP_FEATURE_UNAVAILABLE";
        case MBEDTLS_ERR_ECP_INVALID_KEY:         return "ECP_INVALID_KEY";
        case MBEDTLS_ERR_ECP_ALLOC_FAILED:        return "ECP_ALLOC_FAILED";
        case MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL:    return "ECP_BUFFER_TOO_SMALL";
        case MBEDTLS_ERR_ECP_VERIFY_FAILED:       return "ECP_VERIFY_FAILED";
        case MBEDTLS_ERR_MPI_ALLOC_FAILED:        return "MPI_ALLOC_FAILED";
        case MBEDTLS_ERR_MPI_BAD_INPUT_DATA:      return "MPI_BAD_INPUT_DATA";
        case MBEDTLS_ERR_ENTROPY_SOURCE_FAILED:   return "ENTROPY_SOURCE_FAILED";
        case MBEDTLS_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED: return "CTR_DRBG_ENTROPY_FAILED";
        case MBEDTLS_ERR_CTR_DRBG_REQUEST_TOO_BIG:       return "CTR_DRBG_REQUEST_TOO_BIG";
        case MBEDTLS_ERR_CTR_DRBG_INPUT_TOO_BIG:         return "CTR_DRBG_INPUT_TOO_BIG";
        default:                         return "UNKNOWN";
    }
}

static void logMbedtls(const char* stage, int ret) {
    Serial.printf("[x25519] %-28s ret=0x%04X (%s)\n",
                  stage, (unsigned)ret, mbedtlsErrName(ret));
}

//wymiana kluczy (X25519)

static bool x25519Generate(uint8_t priv[32], uint8_t pub[32]) {
    int ret = 0;

    mbedtls_ecp_keypair       keypair;
    mbedtls_entropy_context   entropy;
    mbedtls_ctr_drbg_context  drbg;
    size_t                    olen = 0;

    mbedtls_ecp_keypair_init(&keypair);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&drbg);

    static const char pers[] = "x25519-gen";
    ret = mbedtls_ctr_drbg_seed(&drbg, mbedtls_entropy_func, &entropy,
                                (const unsigned char*)pers, sizeof(pers) - 1);
    logMbedtls("ctr_drbg_seed", ret);
    if (ret != 0) goto cleanup;

    //generowanie pary kluczy
    ret = mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_CURVE25519,
                              &keypair,
                              mbedtls_ctr_drbg_random, &drbg);
    logMbedtls("ecp_gen_key(CURVE25519)", ret);
    if (ret != 0) goto cleanup;

    //Eksport klucza prywatnego (32 B, little-endian dla Montgomery)
    ret = mbedtls_ecp_write_key_ext(&keypair, &olen, priv, 32);
    logMbedtls("ecp_write_key_ext(priv)", ret);
    if (ret != 0) goto cleanup;

    if (olen != 32) {
        Serial.printf("[x25519] priv key length = %u (expected 32)\n",
                      (unsigned)olen);
        ret = -1;
        goto cleanup;
    }
    logMbedtls("ecp_write_key(priv)", ret);
    if (ret != 0) goto cleanup;

    //Eksport klucza publicznego (32 B, tylko współrzędna X)
    ret = mbedtls_ecp_write_public_key(&keypair,
                                       MBEDTLS_ECP_PF_UNCOMPRESSED,
                                       &olen, pub, 32);
    logMbedtls("ecp_write_public_key", ret);
    if (ret != 0) goto cleanup;

    if (olen != 32) {
        Serial.printf("[x25519] public key length = %u (expected 32)\n",
                      (unsigned)olen);
        ret = -1;
        goto cleanup;
    }

cleanup:
    mbedtls_ecp_keypair_free(&keypair);
    mbedtls_ctr_drbg_free(&drbg);
    mbedtls_entropy_free(&entropy);

    if (ret == 0) {
        Serial.printf("[x25519] OK pub=%02x%02x%02x%02x...\n",
                      pub[0], pub[1], pub[2], pub[3]);
    } else {
        Serial.printf("[x25519] FAILED (ret=0x%04X)\n", (unsigned)ret);
    }
    return ret == 0;
}

static bool x25519Shared(const uint8_t priv[32],
                         const uint8_t peerPub[32],
                         uint8_t out[32]) {
    int ret = 0;

    mbedtls_ecp_group   grp;
    mbedtls_ecp_point   peerQ;
    mbedtls_ecp_point   result;
    mbedtls_mpi         d;
    mbedtls_entropy_context  entropy;
    mbedtls_ctr_drbg_context drbg;
    size_t              olen = 0;

    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_point_init(&peerQ);
    mbedtls_ecp_point_init(&result);
    mbedtls_mpi_init(&d);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&drbg);

    static const char pers[] = "x25519-shared";
    ret = mbedtls_ctr_drbg_seed(&drbg, mbedtls_entropy_func, &entropy,
                                (const unsigned char*)pers, sizeof(pers) - 1);
    logMbedtls("ctr_drbg_seed", ret);
    if (ret != 0) goto cleanup;

    //Załaduj grupę Curve25519
    ret = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_CURVE25519);
    logMbedtls("ecp_group_load(CURVE25519)", ret);
    if (ret != 0) goto cleanup;

    //Wczytaj nasz klucz prywatny jako little-endian
    ret = mbedtls_mpi_read_binary_le(&d, priv, 32);
    logMbedtls("mpi_read_binary_le(priv)", ret);
    if (ret != 0) goto cleanup;

    //Zaimportuj klucz publiczny drugiej strony.
    ret = mbedtls_ecp_point_read_binary(&grp, &peerQ, peerPub, 32);
    logMbedtls("ecp_point_read_binary(peerQ)", ret);
    if (ret != 0) goto cleanup;

    //Oblicz R = priv * peerQ  (mbedtls_ecp_mul)
    //    f_rng != NULL włącza blinding.
    ret = mbedtls_ecp_mul(&grp, &result, &d, &peerQ,
                          mbedtls_ctr_drbg_random, &drbg);
    logMbedtls("ecp_mul(shared)", ret);
    if (ret != 0) goto cleanup;

    // 6) Wspólny sekret = współrzędna X punktu wynikowego.
    //    Eksport przez publiczne mbedtls_ecp_point_write_binary.
    ret = mbedtls_ecp_point_write_binary(&grp, &result,
                                         MBEDTLS_ECP_PF_UNCOMPRESSED,
                                         &olen, out, 32);
    logMbedtls("ecp_point_write_binary(out)", ret);
    if (ret != 0) goto cleanup;

    if (olen != 32) {
        Serial.printf("[x25519] shared secret length = %u (expected 32)\n",
                      (unsigned)olen);
        ret = -1;
        goto cleanup;
    }

cleanup:
    mbedtls_mpi_free(&d);
    mbedtls_ecp_point_free(&peerQ);
    mbedtls_ecp_point_free(&result);
    mbedtls_ecp_group_free(&grp);
    mbedtls_ctr_drbg_free(&drbg);
    mbedtls_entropy_free(&entropy);

    if (ret == 0) {
        Serial.printf("[x25519] shared OK out=%02x%02x%02x%02x...\n",
                      out[0], out[1], out[2], out[3]);
    } else {
        Serial.printf("[x25519] shared FAILED (ret=0x%04X)\n", (unsigned)ret);
    }
    return ret == 0;
}

// HKDF / HMAC

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

//katalog relayów (NVS)

static void loadDefaultRelays() {
    //json relayów
    const char* defaultJson = R"JSON(
    [
      {
        "name": "relay1",
        "ip": "172.16.102.243",
        "port": 8001,
        "pub": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
      },
      {
        "name": "relay2",
        "ip": "172.28.0.12",
        "port": 8002,
        "pub": "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
      },
      {
        "name": "relay3",
        "ip": "172.28.0.13",
        "port": 8003,
        "pub": "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f"
      }
    ]
    )JSON";

    StaticJsonDocument<2048> doc;
    if (deserializeJson(doc, defaultJson) != DeserializationError::Ok) {
        Serial.println("default relay JSON parse failed");
        return;
    }
    gRelayCount = 0;
    for (JsonObject r : doc.as<JsonArray>()) {
        if (gRelayCount >= 8) break;
        Relay& out = gRelays[gRelayCount++];
        IPAddress ip;
        ip.fromString(r["ip"].as<const char*>());
        out.ip   = ipToU32(ip);
        out.port = r["port"].as<uint16_t>();
        strlcpy(out.name, r["name"] | "relay", sizeof(out.name));
        hexToBytes(r["pub"].as<const char*>(), out.x25519Pub, 32);
    }
}

static void loadRelaysFromNVS() {
    gPrefs.begin("relays", true);
    String json = gPrefs.getString("dir", "");
    gPrefs.end();

    if (json.length() == 0) { loadDefaultRelays(); return; }

    StaticJsonDocument<4096> doc;
    if (deserializeJson(doc, json) != DeserializationError::Ok) {
        Serial.println("NVS relay JSON parse failed, using defaults");
        loadDefaultRelays();
        return;
    }
    gRelayCount = 0;
    for (JsonObject r : doc.as<JsonArray>()) {
        if (gRelayCount >= 8) break;
        Relay& out = gRelays[gRelayCount++];
        IPAddress ip;
        ip.fromString(r["ip"].as<const char*>());
        out.ip   = ipToU32(ip);
        out.port = r["port"].as<uint16_t>();
        strlcpy(out.name, r["name"] | "relay", sizeof(out.name));
        hexToBytes(r["pub"].as<const char*>(), out.x25519Pub, 32);
    }
}

// TLS

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

//blokuje zapis aby nie przerwało połączenia za wcześnie

static bool tlsWriteAll(WiFiClientSecure& tls, const uint8_t* buf, size_t len,
                        uint32_t timeoutMs = 10000) {
    size_t total = 0;
    uint32_t deadline = millis() + timeoutMs;
    while (total < len) {
        if (millis() > deadline) {
            Serial.printf("[tls] write timeout at %u/%u\n",
                          (unsigned)total, (unsigned)len);
            return false;
        }
        size_t chunk = (len - total > 128) ? 128 : (len - total);
        size_t n = tls.write(buf + total, chunk);
        if (n > 0) {
            total += n;
        } else if (!tls.connected()) {
            Serial.printf("[tls] peer closed during write at %u/%u\n",
                          (unsigned)total, (unsigned)len);
            return false;
        } else {
            delay(5);
        }
    }
    tls.flush();
    delay(30);   // pozwól mbedTLS wysłać ostatni rekord przed stop()
    return true;
}

//czytanie nie wiszące do timeout

static bool readExactSecure(WiFiClientSecure& c, uint8_t* buf, size_t n,
                            uint32_t timeoutMs = 10000) {
    size_t got = 0;
    uint32_t deadline = millis() + timeoutMs;
    while (got < n) {
        if (millis() > deadline) {
            Serial.printf("[readExact] timeout %u/%u\n",
                          (unsigned)got, (unsigned)n);
            return false;
        }
        int avail = c.available();
        if (avail > 0) {
            int r = c.read(buf + got, n - got);
            if (r > 0) got += r;
        } else if (!c.connected()) {
            Serial.printf("[readExact] peer closed at %u/%u\n",
                          (unsigned)got, (unsigned)n);
            return false;
        } else {
            delay(2);
        }
    }
    return true;
}

// Handshake

static bool handshakeFirstHop(const Relay& relay, CircuitHop& out) {
    IPAddress ip = u32ToIp(relay.ip);
    Serial.printf("[hs] 1/6 TLS connect -> %s:%u\n",
                  ip.toString().c_str(), relay.port);

    WiFiClientSecure tls;
    tls.setInsecure();
    tls.setTimeout(10);              // sekundy
    tls.setHandshakeTimeout(15);     // sekundy
    tls.setNoDelay(true);            // mbedTLS flushuje rekordy od razu
    if (!tls.connect(ip, relay.port)) {
        Serial.printf("[hs] FAIL: connect %s:%u\n",
                      ip.toString().c_str(), relay.port);
        return false;
    }
    Serial.println("[hs] 2/6 TLS connected, generating X25519");

    uint8_t ephPriv[32], ephPub[32];
    if (!x25519Generate(ephPriv, ephPub)) {
        Serial.println("[hs] FAIL: x25519Generate");
        tls.stop();
        return false;
    }
    Serial.printf("[hs] 3/6 ephPub=%02x%02x%02x%02x...\n",
                  ephPub[0], ephPub[1], ephPub[2], ephPub[3]);

    Cell create{};
    create.circuitId = esp_random();
    create.command   = CMD_CREATE;
    memset(create.payload, 0, CELL_PAYLOAD_SIZE);
    memcpy(create.payload, ephPub, HANDSHAKE_PUB_SIZE);
    esp_fill_random(create.payload + HANDSHAKE_PUB_SIZE,
                    CELL_PAYLOAD_SIZE - HANDSHAKE_PUB_SIZE);

    if (!tlsWriteAll(tls, (const uint8_t*)&create, sizeof(create))) {
        Serial.println("[hs] FAIL: CREATE write");
        tls.stop();
        return false;
    }
    Serial.printf("[hs] 4/6 CREATE written (%u B), cid=%08x\n",
                  (unsigned)sizeof(create), create.circuitId);

    Cell created{};
    if (!readExactSecure(tls, (uint8_t*)&created, sizeof(created), 10000)) {
        Serial.println("[hs] FAIL: CREATED read");
        tls.stop();
        return false;
    }
    tls.stop();
    Serial.printf("[hs] 5/6 got cell cid=%08x cmd=%02x\n",
                  created.circuitId, created.command);

    if (created.command != CMD_CREATED) {
        Serial.printf("[hs] FAIL: expected CMD_CREATED(0x02), got 0x%02x\n",
                      created.command);
        return false;
    }
    if (created.circuitId != create.circuitId) {
        Serial.printf("[hs] FAIL: cid mismatch sent=%08x got=%08x\n",
                      create.circuitId, created.circuitId);
        return false;
    }

    uint8_t relayEphPub[HANDSHAKE_PUB_SIZE];
    memcpy(relayEphPub, created.payload, HANDSHAKE_PUB_SIZE);
    Serial.printf("[hs] 6/6 relayEphPub=%02x%02x%02x%02x...\n",
                  relayEphPub[0], relayEphPub[1], relayEphPub[2], relayEphPub[3]);

    uint8_t shared[32];
    if (!x25519Shared(ephPriv, relayEphPub, shared)) {
        Serial.println("[hs] FAIL: x25519Shared");
        return false;
    }
    Serial.printf("[hs] shared=%02x%02x%02x%02x...\n",
                  shared[0], shared[1], shared[2], shared[3]);

    const uint8_t info[] = "onion-hop-v1";
    hkdfSHA256(shared, sizeof(shared), nullptr, 0,
               info, sizeof(info) - 1, out.aesKey, KEY_SIZE);
    Serial.printf("[hs] hopKey=%02x%02x%02x%02x...\n",
                  out.aesKey[0], out.aesKey[1], out.aesKey[2], out.aesKey[3]);

    uint8_t transcript[HANDSHAKE_PUB_SIZE * 2];
    memcpy(transcript, ephPub, HANDSHAKE_PUB_SIZE);
    memcpy(transcript + HANDSHAKE_PUB_SIZE, relayEphPub, HANDSHAKE_PUB_SIZE);

    uint8_t expected[HMAC_SIZE];
    hmacSHA256(out.aesKey, KEY_SIZE, transcript, sizeof(transcript), expected);

    if (memcmp(expected, created.payload + HANDSHAKE_PUB_SIZE, HMAC_SIZE) != 0) {
        Serial.printf("[hs] FAIL: HMAC mismatch exp=%02x%02x%02x%02x got=%02x%02x%02x%02x\n",
                      expected[0], expected[1], expected[2], expected[3],
                      created.payload[HANDSHAKE_PUB_SIZE + 0],
                      created.payload[HANDSHAKE_PUB_SIZE + 1],
                      created.payload[HANDSHAKE_PUB_SIZE + 2],
                      created.payload[HANDSHAKE_PUB_SIZE + 3]);
        return false;
    }

    out.circuitId = create.circuitId;
    out.active    = true;
    Serial.println("[hs] SUCCESS");
    return true;
}

// EXTEND – przedłużenie obwodu przez istniejące połączenie

// Buduje komórkę RELAY z komendą EXTEND, która zostanie wysłana do
// ostatniego hopa. Payload EXTEND zawiera:
//   nextIP(4), nextPort(2), ephPub(32), HMAC(32), padding
// Całość jest szyfrowana kluczem ostatniego hopa

static bool sendExtendToLastHop(const Relay& nextRelay) {
    if (gHopCount == 0 || gHopCount >= MAX_HOPS) return false;

    uint8_t ephPriv[32], ephPub[32];
    if (!x25519Generate(ephPriv, ephPub)) return false;

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

    //odszyfruj K1, K2, …, K_last
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

    //wylicz klucz nowego hopa
    uint8_t shared[32];
    if (!x25519Shared(ephPriv, relayEphPub, shared)) return false;

    uint8_t newKey[KEY_SIZE];
    const uint8_t info[] = "onion-hop-v1";
    hkdfSHA256(shared, sizeof(shared), nullptr, 0,
               info, sizeof(info) - 1, newKey, KEY_SIZE);

    //weryfikacja HMAC od nowego hopa
    uint8_t transcript[HANDSHAKE_PUB_SIZE * 2];
    memcpy(transcript, ephPub, HANDSHAKE_PUB_SIZE);
    memcpy(transcript + HANDSHAKE_PUB_SIZE, relayEphPub, HANDSHAKE_PUB_SIZE);
    uint8_t expected[HMAC_SIZE];
    hmacSHA256(newKey, KEY_SIZE, transcript, sizeof(transcript), expected);

    if (memcmp(expected, receivedHmac, HMAC_SIZE) != 0) {
        Serial.println("EXTENDED HMAC mismatch");
        return false;
    }

    gCircuit[gHopCount].circuitId = 0;
    memcpy(gCircuit[gHopCount].aesKey, newKey, KEY_SIZE);
    gCircuit[gHopCount].active = true;
    gHopCount++;

    Serial.printf("EXTEND -> %s ok, hops=%u\n", nextRelay.name, gHopCount);
    return true;
}

// Budowa cebuli

// Buduje cebulę dla docelowego adresu, używając kluczy wszystkich
// aktywnych hopów w gCircuit. Wynik to finalny pakiet gotowy do wysłania

static size_t buildOnion(uint32_t finalIP, uint16_t finalPort,
                         const uint8_t* data, size_t dataLen,
                         uint8_t* outCipher) {
    if (gHopCount == 0 || dataLen > RELAY_MAX_INNER) return 0;

    //faktyczna wiadomość
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

        //Adres następnego hopa
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

    memcpy(outCipher, cipher, cipherLen);
    return cipherLen;
}

// Wysłanie komórki RELAY do entry relay

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

//połączenie wifi

static void connectWiFi() {
    Serial.printf("Connecting to %s\n", SSID);
    WiFi.mode(WIFI_STA);
    WiFi.begin(SSID, PASSWORD);
    while (WiFi.status() != WL_CONNECTED) {
        delay(500);
        Serial.print('.');
    }
    Serial.printf("\nConnected, IP=%s\n", WiFi.localIP().toString().c_str());
}

//Prototyp: budowa obwodu i wysłanie danych

static void runOnionDemo() {
    if (gRelayCount < 3) {
        Serial.println("Need at least 3 relays");
        return;
    }

    //Reset stanu obwodu
    gHopCount = 0;
    memset(gCircuit, 0, sizeof(gCircuit));

    //Hop 1: bezpośredni handshake
    Serial.printf("Creating first hop with %s...\n", gRelays[0].name);
    if (!handshakeFirstHop(gRelays[0], gCircuit[0])) {
        Serial.println("First-hop handshake failed");
        return;
    }
    gHopCount = 1;

    //Hop 2: EXTEND
    Serial.printf("Extending to %s...\n", gRelays[1].name);
    if (!sendExtendToLastHop(gRelays[1])) {
        Serial.println("EXTEND to hop 2 failed");
        return;
    }

    //Hop 3: EXTEND
    Serial.printf("Extending to %s...\n", gRelays[2].name);
    if (!sendExtendToLastHop(gRelays[2])) {
        Serial.println("EXTEND to hop 3 failed");
        return;
    }

    Serial.printf("Circuit established with %u hops\n", gHopCount);

    //Wyślij dane przez gotowy obwód
    const uint32_t DEST_IP   = 0xAC1C0014;   // 172.28.0.20
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

//zadanie
void onionTask(void* /*arg*/) {
    for (;;) {
        runOnionDemo();
        vTaskDelay(pdMS_TO_TICKS(15000));
    }
}

void setup() {
    Serial.begin(115200);
    delay(200);

    loadRelaysFromNVS();
    Serial.printf("Loaded %u relays\n", gRelayCount);

    connectWiFi();

    uint8_t dummy[32];
    esp_fill_random(dummy, sizeof(dummy)); // rozgrzanie entropii

    xTaskCreatePinnedToCore(
        onionTask,          // funkcja zadania
        "onion",            // nazwa
        32768,              // stos: 32 KB
        nullptr,            // argument
        1,                  // priorytet
        nullptr,            // handle
        1                   // rdzeń (1 = APP_CPU)
    );    
}

void loop() {
    // puste – cała praca w onionTask
    vTaskDelay(pdMS_TO_TICKS(1000));
}