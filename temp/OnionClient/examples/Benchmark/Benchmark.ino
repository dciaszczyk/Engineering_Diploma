// Porównanie kosztu wysłania małej wiadomości na ESP32: onion vs HTTP, HTTPS, MQTT i CoAP.
// Mierzy czas, szczyt zużycia sterty i (dla onion) zapas stosu. Bajty na łączu liczą proxy po stronie PC.
//
// PC w tej samej sieci:  python3 extras/bench/serve_lan.py --ip <adres PC>
// Szkic: ustaw WIFI_*, HOST (adres PC) i wgraj. Wyniki idą na Serial po ok. minucie.
#include <HTTPClient.h>
#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <WiFiUdp.h>
#include <OnionClient.h>

const char* WIFI_SSID     = "ssid";
const char* WIFI_PASSWORD = "password";
const char* HOST          = "192.168.1.10";   // adres PC z serve_lan.py
const int   N             = 10;               // wiadomości na scenariusz
const size_t PAYLOAD      = 64;

uint8_t payload[PAYLOAD];

// ---- pomiar zużycia sterty: zadanie próbkujące najmniejszą wolną stertę w trakcie scenariusza ----
volatile uint32_t gMinFree = 0;
volatile bool     gSampling = false;

void samplerTask(void*) {
    for (;;) {
        if (gSampling) {
            uint32_t f = ESP.getFreeHeap();
            if (f < gMinFree) gMinFree = f;
        }
        vTaskDelay(1);
    }
}

// Wynik jednej wiadomości dla onion (callback klienta).
volatile int gOnionDone = 0;
volatile onion::SendStatus gOnionStatus = onion::SendStatus::Failed;
void onOnion(const onion::SendResult& r) { gOnionStatus = r.status; gOnionDone++; }

// ---- jednowiadomościowe wysyłki (każda zwraca true, gdy się udała) ----
bool httpPost() {
    HTTPClient http;
    http.begin(HOST, 19601, "/data");
    int code = http.POST(payload, PAYLOAD);
    http.end();
    return code == 200;
}

bool httpsPost() {
    WiFiClientSecure tls;
    tls.setInsecure();
    HTTPClient http;
    http.begin(tls, HOST, 19602, "/data", true);
    int code = http.POST(payload, PAYLOAD);
    http.end();
    return code == 200;
}

// MQTT 3.1.1 QoS 1 w minimalnej postaci: CONNECT, PUBLISH, DISCONNECT (te same pakiety co w bench.py).
bool readExact(WiFiClient& c, uint8_t* buf, size_t n) {
    uint32_t end = millis() + 3000;
    for (size_t got = 0; got < n;) {
        if (c.available()) buf[got++] = c.read();
        else if (millis() > end || !c.connected()) return false;
        else delay(1);
    }
    return true;
}

bool mqttPublish() {
    WiFiClient c;
    if (!c.connect(HOST, 19603)) return false;
    const uint8_t connect[] = {0x10, 0x12, 0x00, 0x04, 'M', 'Q', 'T', 'T', 0x04, 0x02, 0x00, 0x3c, 0x00, 0x06, 's', 'e', 'n', 's', 'o', 'r'};
    c.write(connect, sizeof(connect));
    uint8_t ack[4];
    if (!readExact(c, ack, 4)) return false;                       // CONNACK

    // PUBLISH QoS 1: nagłówek(2) | temat "t/dt" z długością(6) | id pakietu(2) | dane
    const size_t body = 6 + 2 + PAYLOAD;                           // 72 B: mieści się w jednym bajcie długości
    static_assert(body < 128, "dłuższe pakiety wymagają wielobajtowej długości MQTT");
    uint8_t pub[2 + body];
    size_t n = 0;
    pub[n++] = 0x32;                                               // PUBLISH, QoS 1
    pub[n++] = (uint8_t)body;
    pub[n++] = 0x00; pub[n++] = 0x04; pub[n++] = 't'; pub[n++] = '/'; pub[n++] = 'd'; pub[n++] = 't';
    pub[n++] = 0x00; pub[n++] = 0x01;                              // id pakietu
    memcpy(pub + n, payload, PAYLOAD);
    n += PAYLOAD;
    c.write(pub, n);
    bool ok = readExact(c, ack, 4);                                // PUBACK
    const uint8_t bye[] = {0xe0, 0x00};
    c.write(bye, 2);
    c.stop();
    return ok;
}

// CoAP CON POST /data po UDP, czeka na ACK.
bool coapPost() {
    static uint16_t mid = 0;
    WiFiUDP udp;
    uint8_t msg[8 + PAYLOAD + 8];
    size_t n = 0;
    msg[n++] = 0x42; msg[n++] = 0x02;                              // CON, 2 B tokenu, POST
    mid++; msg[n++] = mid >> 8; msg[n++] = mid;
    msg[n++] = 0xAA; msg[n++] = 0xBB;                              // token
    msg[n++] = 0xB4; memcpy(msg + n, "data", 4); n += 4;           // Uri-Path: data
    msg[n++] = 0xFF;
    memcpy(msg + n, payload, PAYLOAD); n += PAYLOAD;
    udp.beginPacket(HOST, 19605);
    udp.write(msg, n);
    udp.endPacket();
    uint32_t end = millis() + 2000;
    while (millis() < end) {
        if (udp.parsePacket() > 0) { uint8_t ack[16]; udp.read(ack, sizeof(ack)); udp.stop(); return ack[1] == 0x44; }
        delay(1);
    }
    udp.stop();
    return false;
}

// ---- onion ----
onion::Client clientNew, clientReuse;
onion::Relay  relays[onion::MAX_RELAYS];
size_t        relayCount = 0;
uint32_t      destIp = 0;
bool          onionReady = false;

bool onionSend(onion::Client& c) {
    int before = gOnionDone;
    if (!c.send(destIp, 9000, payload, PAYLOAD)) return false;
    uint32_t end = millis() + 60000;
    while (gOnionDone == before && millis() < end) delay(5);
    return gOnionDone != before && gOnionStatus == onion::SendStatus::Delivered;
}

// ---- pętla pomiarowa ----
void run(const char* name, bool (*fn)(), onion::Client* onionClient = nullptr) {
    uint32_t baseline = ESP.getFreeHeap();
    gMinFree = baseline;
    gSampling = true;
    uint32_t total = 0, lo = 0xFFFFFFFF, hi = 0;
    int ok = 0;
    for (int i = 0; i < N; i++) {
        uint32_t t0 = millis();
        bool good = fn();
        uint32_t dt = millis() - t0;
        if (good) { ok++; total += dt; if (dt < lo) lo = dt; if (dt > hi) hi = dt; }
        delay(200);
    }
    gSampling = false;
    Serial.printf("%-34s ok %2d/%d  avg %5u ms  min %5u  max %5u  heap peak %6u B", name, ok, N,
                  ok ? (unsigned)(total / ok) : 0, ok ? (unsigned)lo : 0, (unsigned)hi, (unsigned)(baseline - gMinFree));
    if (onionClient) Serial.printf("  task stack free min %u B", (unsigned)onionClient->stackFreeMin());
    Serial.println();
}

bool onionNewCircuit() { return onionSend(clientNew); }
bool onionReused()     { return onionSend(clientReuse); }

void setup() {
    Serial.begin(115200);
    delay(300);
    for (size_t i = 0; i < PAYLOAD; i++) payload[i] = (uint8_t)(i * 7 + 3);

    WiFi.mode(WIFI_STA);
    WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
    while (WiFi.status() != WL_CONNECTED) delay(300);
    Serial.printf("Connected, IP=%s, free heap %u B\n", WiFi.localIP().toString().c_str(), (unsigned)ESP.getFreeHeap());
    IPAddress h; h.fromString(HOST);
    destIp = onion::ipToU32(h);

    xTaskCreatePinnedToCore(samplerTask, "heap-sampler", 2048, nullptr, 1, nullptr, 0);

    char dirUrl[48];
    snprintf(dirUrl, sizeof(dirUrl), "http://%s:8080", HOST);
    relayCount = onion::fetchNodes(dirUrl, "relay", relays);
    Serial.printf("Directory: %u relays\n", (unsigned)relayCount);

    onion::ClientConfig cfg;                    // 3 losowe hopy
    cfg.reuseCircuit = false;
    onionReady = relayCount >= 3 && clientNew.begin(relays, relayCount, cfg);
    cfg.reuseCircuit = true;
    onionReady = onionReady && clientReuse.begin(relays, relayCount, cfg);
    clientNew.onResult(onOnion);
    clientReuse.onResult(onOnion);

    Serial.printf("\n%u wiadomości po %u B na scenariusz (czas i szczyt sterty na wiadomość)\n", N, (unsigned)PAYLOAD);
    run("HTTP/1.1, conn per message", httpPost);
    run("HTTPS, conn per message", httpsPost);
    run("MQTT QoS1, conn per message", mqttPublish);
    run("CoAP CON (UDP)", coapPost);
    if (onionReady) {
        run("onion 3 hops, new circuit/msg", onionNewCircuit, &clientNew);
        run("onion 3 hops, circuit reused", onionReused, &clientReuse);
    } else {
        Serial.println("onion: need >= 3 relays in the directory (is serve_lan.py running?)");
    }
    Serial.println("\nBajty na łączu: zobacz wydruk serve_lan.py (liczniki proxy).");
}

void loop() { delay(1000); }
