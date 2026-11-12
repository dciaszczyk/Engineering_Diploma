// =====================================================================
// onion_relay.ino — MCU relay kompatybilny z Python serwer.py
// =====================================================================
#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/pk.h>
#include <mbedtls/aes.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/ecp.h>
#include <mbedtls/hkdf.h>
#include <mbedtls/md.h>
#include <esp_random.h>

// ---------------- config (edit) ----------------
const char* SSID     = "iprivate-4";
const char* PASSWORD = "Tciaszczyk1980";
#define MY_PORT 8002        // 8001/8002/8003 – wybierz rolę
// -----------------------------------------------

// ---------------- protocol ----------------
#define CELL_SIZE         514
#define CELL_PAYLOAD_SIZE 509
#define CMD_CREATE   0x01
#define CMD_CREATED  0x02
#define CMD_RELAY    0x03
#define CMD_DESTROY  0x04
#define RCMD_EXTEND  0x10
#define RCMD_EXTENDED 0x11
#define RCMD_DATA    0x12
#define IV_SIZE      16
#define KEY_SIZE     32
#define PUB_SIZE     32
#define HMAC_SIZE    32
#define HDR          9
#define MAX_CIRCUITS 8
#define OUT_TIMEOUT_MS 10000

// ---------------- cert (paste) ----------------
const char* CERT_PEM = R"CRT(
-----BEGIN CERTIFICATE-----
PASTE_YOUR_CERT_HERE
-----END CERTIFICATE-----
)CRT";
const char* KEY_PEM = R"KEY(
-----BEGIN RSA PRIVATE KEY-----
PASTE_YOUR_KEY_HERE
-----END RSA PRIVATE KEY-----
)KEY";

// ---------------- circuit state ----------------
struct CircuitState {
    uint32_t circuitId;
    uint8_t  hopKey[KEY_SIZE];
    uint32_t nextIp;
    uint16_t nextPort;
    uint32_t nextCircuitId;
    bool     nextSet;
    bool     active;
};
CircuitState gCircuits[MAX_CIRCUITS];

// ---------------- mbedTLS server (shared) ----------------
static mbedtls_entropy_context  gEntropy;
static mbedtls_ctr_drbg_context gDrbg;
static mbedtls_x509_crt         gCert;
static mbedtls_pk_context       gKey;
static mbedtls_ssl_config       gConf;

WiFiServer gTcpServer(MY_PORT);

// =====================================================================
// Crypto helpers (identyczne z klientem)
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

static size_t aesDecrypt(const uint8_t* data, size_t len,
                         const uint8_t* key, uint8_t* out) {
    if (len < IV_SIZE) return 0;
    uint8_t iv[IV_SIZE];
    memcpy(iv, data, IV_SIZE);
    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);
    mbedtls_aes_setkey_enc(&ctx, key, 256);
    size_t nc_off = 0;
    uint8_t nonce[16], stream[16];
    memcpy(nonce, iv, 16);
    memset(stream, 0, 16);
    size_t plainLen = len - IV_SIZE;
    mbedtls_aes_crypt_ctr(&ctx, plainLen, &nc_off, nonce, stream, data + IV_SIZE, out);
    mbedtls_aes_free(&ctx);
    return plainLen;
}

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

static bool x25519Keypair(uint8_t priv[32], uint8_t pub[32]) {
    mbedtls_ecdh_context ctx;
    mbedtls_ecdh_init(&ctx);
    if (mbedtls_ecp_group_load(&ctx.grp, MBEDTLS_ECP_DP_CURVE25519) != 0) {
        mbedtls_ecdh_free(&ctx); return false;
    }
    int ret = mbedtls_ecdh_gen_public(&ctx.grp, &ctx.d, &ctx.Q,
                                      mbedtls_ctr_drbg_random, &gDrbg);
    if (ret == 0) {
        mbedtls_mpi_write_binary(&ctx.d, priv, 32);
        mbedtls_mpi_write_binary(&ctx.Q.X, pub, 32);
    }
    mbedtls_ecdh_free(&ctx);
    return ret == 0;
}

static bool x25519Shared(const uint8_t priv[32], const uint8_t peerPub[32],
                         uint8_t out[32]) {
    mbedtls_ecdh_context ctx;
    mbedtls_ecdh_init(&ctx);
    if (mbedtls_ecp_group_load(&ctx.grp, MBEDTLS_ECP_DP_CURVE25519) != 0) {
        mbedtls_ecdh_free(&ctx); return false;
    }
    mbedtls_mpi_read_binary(&ctx.d, priv, 32);
    if (mbedtls_ecdh_read_public(&ctx, peerPub, 32) != 0) {
        mbedtls_ecdh_free(&ctx); return false;
    }
    mbedtls_mpi z; mbedtls_mpi_init(&z);
    int ret = mbedtls_ecdh_compute_shared(&ctx.grp, &z, &ctx.Qp, &ctx.d,
                                          mbedtls_ctr_drbg_random, &gDrbg);
    if (ret == 0) mbedtls_mpi_write_binary(&z, out, 32);
    mbedtls_mpi_free(&z);
    mbedtls_ecdh_free(&ctx);
    return ret == 0;
}

// =====================================================================
// Helpers
// =====================================================================
static IPAddress u32ToIp(uint32_t ip) {
    return IPAddress((ip >> 24) & 0xFF, (ip >> 16) & 0xFF,
                     (ip >> 8) & 0xFF, ip & 0xFF);
}

static int findCircuit(uint32_t cid) {
    for (int i = 0; i < MAX_CIRCUITS; i++)
        if (gCircuits[i].active && gCircuits[i].circuitId == cid) return i;
    return -1;
}

static int allocCircuit(uint32_t cid) {
    int existing = findCircuit(cid);
    if (existing >= 0) return existing;
    for (int i = 0; i < MAX_CIRCUITS; i++) {
        if (!gCircuits[i].active) {
            memset(&gCircuits[i], 0, sizeof(CircuitState));
            gCircuits[i].active = true;
            gCircuits[i].circuitId = cid;
            return i;
        }
    }
    return -1;
}

// =====================================================================
// TLS bio + read/write
// =====================================================================
static int bioSend(void* ctx, const unsigned char* buf, size_t len) {
    WiFiClient* c = static_cast<WiFiClient*>(ctx);
    return c->write(buf, len);
}

static int bioRecv(void* ctx, unsigned char* buf, size_t len) {
    WiFiClient* c = static_cast<WiFiClient*>(ctx);
    uint32_t start = millis();
    while (!c->available()) {
        if (!c->connected() || millis() - start > 1000)
            return MBEDTLS_ERR_SSL_CONN_EOF;
        delay(5);
    }
    int r = c->read(buf, len);
    return r > 0 ? r : MBEDTLS_ERR_SSL_CONN_EOF;
}

static bool readExactSsl(mbedtls_ssl_context* ssl, uint8_t* buf, size_t n) {
    size_t got = 0;
    while (got < n) {
        int r = mbedtls_ssl_read(ssl, buf + got, n - got);
        if (r <= 0) return false;
        got += r;
    }
    return true;
}

static bool readExactTls(WiFiClientSecure& c, uint8_t* buf, size_t n,
                         uint32_t timeoutMs = OUT_TIMEOUT_MS) {
    size_t got = 0;
    uint32_t deadline = millis() + timeoutMs;
    while (got < n) {
        if (millis() > deadline || !c.connected()) return false;
        if (c.available()) {
            int r = c.read(buf + got, n - got);
            if (r > 0) got += r;
        } else delay(5);
    }
    return true;
}

// =====================================================================
// Handlery komórek
// =====================================================================
static void handleCreate(mbedtls_ssl_context* ssl, uint32_t cid,
                         const uint8_t* payload) {
    const uint8_t* clientPub = payload;
    uint8_t priv[32], pub[32];
    if (!x25519Keypair(priv, pub)) return;

    uint8_t shared[32];
    if (!x25519Shared(priv, clientPub, shared)) return;

    uint8_t hopKey[KEY_SIZE];
    const uint8_t info[] = "onion-hop-v1";
    hkdfSHA256(shared, 32, nullptr, 0, info, sizeof(info) - 1, hopKey, KEY_SIZE);

    uint8_t transcript[64];
    memcpy(transcript, clientPub, 32);
    memcpy(transcript + 32, pub, 32);
    uint8_t hmac[HMAC_SIZE];
    hmacSHA256(hopKey, KEY_SIZE, transcript, 64, hmac);

    int idx = allocCircuit(cid);
    if (idx < 0) { Serial.println("circuit table full"); return; }
    memcpy(gCircuits[idx].hopKey, hopKey, KEY_SIZE);
    gCircuits[idx].nextSet = false;
    gCircuits[idx].active = true;

    uint8_t resp[CELL_SIZE];
    memcpy(resp, &cid, 4);
    resp[4] = CMD_CREATED;
    memcpy(resp + 5, pub, 32);
    memcpy(resp + 5 + 32, hmac, 32);
    esp_fill_random(resp + 5 + 64, CELL_SIZE - 5 - 64);
    mbedtls_ssl_write(ssl, resp, CELL_SIZE);
    Serial.printf("CREATE cid=%08x ok\n", cid);
}

static void handleExtend(mbedtls_ssl_context* ssl, uint32_t cid,
                         CircuitState* st, uint32_t nextIp, uint16_t nextPort,
                         const uint8_t* inner, size_t innerLen) {
    if (innerLen < PUB_SIZE) return;
    const uint8_t* nextClientPub = inner;

    WiFiClientSecure out;
    out.setInsecure();
    out.setTimeout(OUT_TIMEOUT_MS / 1000);
    IPAddress ip = u32ToIp(nextIp);
    if (!out.connect(ip, nextPort)) {
        Serial.printf("EXTEND connect %s:%u fail\n",
                      ip.toString().c_str(), nextPort);
        return;
    }

    uint32_t newCid = esp_random();
    uint8_t createCell[CELL_SIZE];
    memcpy(createCell, &newCid, 4);
    createCell[4] = CMD_CREATE;
    memcpy(createCell + 5, nextClientPub, PUB_SIZE);
    esp_fill_random(createCell + 5 + PUB_SIZE, CELL_SIZE - 5 - PUB_SIZE);
    out.write(createCell, CELL_SIZE);

    uint8_t createdCell[CELL_SIZE];
    if (!readExactTls(out, createdCell, CELL_SIZE)) { out.stop(); return; }
    out.stop();

    uint32_t respCid;
    memcpy(&respCid, createdCell, 4);
    if (createdCell[4] != CMD_CREATED || respCid != newCid) return;

    st->nextIp = nextIp;
    st->nextPort = nextPort;
    st->nextCircuitId = newCid;
    st->nextSet = true;

    // EXTENDED: target=0:0, rcmd=EXTENDED, payload=eph_pub(32)+hmac(32)
    uint8_t plain[CELL_PAYLOAD_SIZE - IV_SIZE];   // 493
    memset(plain, 0, sizeof(plain));
    uint32_t zero = 0;
    uint16_t zeroPort = 0;
    uint16_t extLen = PUB_SIZE + HMAC_SIZE;
    memcpy(plain, &zero, 4);
    memcpy(plain + 4, &zeroPort, 2);
    plain[6] = RCMD_EXTENDED;
    memcpy(plain + 7, &extLen, 2);
    memcpy(plain + 9, createdCell + 5, extLen);

    uint8_t enc[CELL_PAYLOAD_SIZE];
    aesEncrypt(plain, sizeof(plain), st->hopKey, enc);   // 509 B

    uint8_t resp[CELL_SIZE];
    memcpy(resp, &cid, 4);
    resp[4] = CMD_RELAY;
    memcpy(resp + 5, enc, CELL_PAYLOAD_SIZE);
    mbedtls_ssl_write(ssl, resp, CELL_SIZE);
    Serial.printf("EXTEND %s:%u ok cid=%08x\n",
                  u32ToIp(nextIp).toString().c_str(), nextPort, newCid);
}

static void handleData(mbedtls_ssl_context* ssl, uint32_t cid, CircuitState* st,
                       uint32_t targetIp, uint16_t targetPort,
                       const uint8_t* inner, size_t innerLen) {
    if (!st->nextSet) {
        // exit: raw TCP do celu
        IPAddress ip = u32ToIp(targetIp);
        WiFiClient exit;
        exit.setTimeout(5);
        if (exit.connect(ip, targetPort)) {
            exit.write(inner, innerLen);
            exit.stop();
            Serial.printf("EXIT %s:%u %u B\n",
                          ip.toString().c_str(), targetPort, (unsigned)innerLen);
        } else {
            Serial.printf("EXIT connect %s:%u fail\n",
                          ip.toString().c_str(), targetPort);
        }
        return;  // brak odpowiedzi — zgodne z Python serwer.py
    }

    // forward do następnego hopa
    WiFiClientSecure out;
    out.setInsecure();
    out.setTimeout(OUT_TIMEOUT_MS / 1000);
    IPAddress ip = u32ToIp(st->nextIp);
    if (!out.connect(ip, st->nextPort)) {
        Serial.println("FORWARD connect fail");
        return;
    }

    uint8_t fwd[CELL_SIZE];
    memcpy(fwd, &st->nextCircuitId, 4);
    fwd[4] = CMD_RELAY;
    memcpy(fwd + 5, inner, innerLen);
    if (innerLen < CELL_PAYLOAD_SIZE)
        esp_fill_random(fwd + 5 + innerLen, CELL_PAYLOAD_SIZE - innerLen);
    out.write(fwd, CELL_SIZE);

    uint8_t resp[CELL_SIZE];
    if (!readExactTls(out, resp, CELL_SIZE, 2000)) {   // krótki timeout – exit nie odpowiada
        out.stop();
        return;
    }
    out.stop();
    if (resp[4] != CMD_RELAY) return;

    // wrap odpowiedzi (zgodnie z Python: aes_encrypt(509) obcięte do 509)
    uint8_t wrapped[CELL_PAYLOAD_SIZE + IV_SIZE];
    aesEncrypt(resp + 5, CELL_PAYLOAD_SIZE, st->hopKey, wrapped);
    uint8_t outCell[CELL_SIZE];
    memcpy(outCell, &cid, 4);
    outCell[4] = CMD_RELAY;
    memcpy(outCell + 5, wrapped, CELL_PAYLOAD_SIZE);
    mbedtls_ssl_write(ssl, outCell, CELL_SIZE);
    Serial.printf("FORWARD cid=%08x -> %08x\n", cid, st->nextCircuitId);
}

static void handleRelay(mbedtls_ssl_context* ssl, uint32_t cid,
                        const uint8_t* payload) {
    int idx = findCircuit(cid);
    if (idx < 0) { Serial.printf("RELAY unknown cid=%08x\n", cid); return; }
    CircuitState* st = &gCircuits[idx];

    uint8_t plain[CELL_PAYLOAD_SIZE];
    size_t plainLen = aesDecrypt(payload, CELL_PAYLOAD_SIZE, st->hopKey, plain);
    if (plainLen < HDR) return;

    uint32_t targetIp;
    uint16_t targetPort, payloadLen;
    uint8_t rcmd;
    memcpy(&targetIp, plain, 4);
    memcpy(&targetPort, plain + 4, 2);
    rcmd = plain[6];
    memcpy(&payloadLen, plain + 7, 2);
    if (HDR + payloadLen > plainLen) return;

    const uint8_t* inner = plain + HDR;
    Serial.printf("RELAY cid=%08x rcmd=%02x -> %s:%u (%u B)\n",
                  cid, rcmd, u32ToIp(targetIp).toString().c_str(),
                  targetPort, (unsigned)payloadLen);

    if (rcmd == RCMD_EXTEND)
        handleExtend(ssl, cid, st, targetIp, targetPort, inner, payloadLen);
    else if (rcmd == RCMD_DATA)
        handleData(ssl, cid, st, targetIp, targetPort, inner, payloadLen);
}

// =====================================================================
// Połączenie TLS (server-side)
// =====================================================================
static void handleConnection(WiFiClient& incoming) {
    mbedtls_ssl_context ssl;
    mbedtls_ssl_init(&ssl);
    if (mbedtls_ssl_setup(&ssl, &gConf) != 0) { mbedtls_ssl_free(&ssl); return; }
    mbedtls_ssl_set_bio(&ssl, &incoming, bioSend, bioRecv, bioRecv);

    int ret = mbedtls_ssl_handshake(&ssl);
    if (ret != 0) { mbedtls_ssl_free(&ssl); return; }

    while (true) {
        uint8_t cell[CELL_SIZE];
        if (!readExactSsl(&ssl, cell, CELL_SIZE)) break;

        uint32_t cid;
        memcpy(&cid, cell, 4);
        uint8_t cmd = cell[4];
        const uint8_t* payload = cell + 5;

        if (cmd == CMD_CREATE) {
            handleCreate(&ssl, cid, payload);
        } else if (cmd == CMD_RELAY) {
            handleRelay(&ssl, cid, payload);
        } else if (cmd == CMD_DESTROY) {
            int idx = findCircuit(cid);
            if (idx >= 0) gCircuits[idx].active = false;
            Serial.printf("DESTROY cid=%08x\n", cid);
        } else {
            Serial.printf("unknown cmd %02x\n", cmd);
        }
    }

    mbedtls_ssl_close_notify(&ssl);
    mbedtls_ssl_free(&ssl);
}

// =====================================================================
// WiFi + setup
// =====================================================================
static void connectWiFi() {
    WiFi.mode(WIFI_STA);
    WiFi.begin(SSID, PASSWORD);
    while (WiFi.status() != WL_CONNECTED) { delay(500); Serial.print('.'); }
    Serial.printf("\nIP: %s\n", WiFi.localIP().toString().c_str());
}

void setup() {
    Serial.begin(115200);
    delay(200);
    Serial.printf("=== MCU relay port %u ===\n", MY_PORT);

    connectWiFi();

    mbedtls_entropy_init(&gEntropy);
    mbedtls_ctr_drbg_init(&gDrbg);
    mbedtls_ctr_drbg_seed(&gDrbg, mbedtls_entropy_func, &gEntropy, nullptr, 0);

    mbedtls_x509_crt_init(&gCert);
    if (mbedtls_x509_crt_parse(&gCert,
            (const unsigned char*)CERT_PEM, strlen(CERT_PEM) + 1) != 0) {
        Serial.println("CERT parse failed!"); return;
    }
    mbedtls_pk_init(&gKey);
    if (mbedtls_pk_parse_key(&gKey,
            (const unsigned char*)KEY_PEM, strlen(KEY_PEM) + 1, nullptr, 0) != 0) {
        Serial.println("KEY parse failed!"); return;
    }

    mbedtls_ssl_config_init(&gConf);
    mbedtls_ssl_config_defaults(&gConf, MBEDTLS_SSL_IS_SERVER,
                                MBEDTLS_SSL_TRANSPORT_STREAM,
                                MBEDTLS_SSL_PRESET_DEFAULT);
    mbedtls_ssl_conf_rng(&gConf, mbedtls_ctr_drbg_random, &gDrbg);
    mbedtls_ssl_conf_own_cert(&gConf, &gCert, &gKey);

    gTcpServer.begin();
    Serial.println("TLS server started");

    uint8_t dummy[32]; esp_fill_random(dummy, sizeof(dummy));
}

void loop() {
    WiFiClient incoming = gTcpServer.available();
    if (!incoming) { delay(10); return; }
    Serial.printf("TLS conn from %s\n", incoming.remoteIP().toString().c_str());
    handleConnection(incoming);
    incoming.stop();
    delay(10);
}