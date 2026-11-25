// Klient: wysyła wiadomość przez 3 losowe relaye i odbiera odpowiedź celu.
// Relaye bierze z katalogu (extras/python/directory.py), a jeśli go nie ma, z NVS albo z listy wbudowanej.
#include <WiFi.h>
#include <OnionClient.h>

const char* WIFI_SSID     = "iprivate-4";
const char* WIFI_PASSWORD = "Tciaszczyk1980";

// Katalog relayów i celów (miniserwer Pythona). Relaye rejestrują się w nim same po starcie.
// nullptr = bez katalogu (lista z NVS albo DEFAULT_RELAYS poniżej).
const char* DIRECTORY_URL = "http://172.28.0.2:8080";

// Cel wiadomości: 172.28.0.20:9000. Jeśli cel zarejestrował się w katalogu jako "service" o nazwie
// DEST_NAME, wiadomość jest szyfrowana end-to-end jego kluczem: exit i relaye nie widzą treści.
const uint32_t DEST_IP   = onion::ipToU32(IPAddress(172, 28, 0, 20));
const uint16_t DEST_PORT = 9000;
const char*    DEST_NAME = "secure";

// Lista awaryjna, gdy brak katalogu. W NVS (namespace "relays", klucz "dir") można ją podmienić bez
// przeflashowywania (patrz README). Pole "pub" musi być PRAWDZIWYM statycznym kluczem publicznym relaya
// (relay wypisuje go przy starcie); wartości 00..1f to zaślepki i handshake z nimi się nie uda.
const char* DEFAULT_RELAYS = R"JSON(
[
  { "name": "relay1", "ip": "172.16.102.243", "port": 8001,
    "pub": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" },
  { "name": "relay2", "ip": "172.28.0.12", "port": 8002,
    "pub": "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f" },
  { "name": "relay3", "ip": "172.28.0.13", "port": 8003,
    "pub": "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f" }
]
)JSON";

onion::Relay  relays[onion::MAX_RELAYS];
onion::Relay  services[4];
onion::Client client;
bool          haveDestKey = false;
uint8_t       destKey[32];

// Wynik każdej wiadomości (numer = wartość zwrócona przez send()) i odpowiedź celu.
void onResult(const onion::SendResult& r) {
    Serial.printf("message #%u: %s", (unsigned)r.seq, onion::statusName(r.status));
    if (r.responseLen) Serial.printf(", response: %.*s", (int)r.responseLen, (const char*)r.response);
    Serial.println();
}

void setup() {
    Serial.begin(115200);
    delay(200);

    WiFi.mode(WIFI_STA);
    WiFi.setAutoReconnect(true);
    WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
    while (WiFi.status() != WL_CONNECTED) {
        delay(500);
        Serial.print('.');
    }
    Serial.printf("\nConnected, IP=%s\n", WiFi.localIP().toString().c_str());

    // 1. relaye: katalog -> NVS -> lista wbudowana
    size_t n = DIRECTORY_URL ? onion::fetchNodes(DIRECTORY_URL, "relay", relays) : 0;
    if (n == 0) n = onion::loadRelaysFromNVS(relays);
    if (n == 0) n = onion::parseRelays(DEFAULT_RELAYS, relays);
    Serial.printf("Loaded %u relays\n", (unsigned)n);

    // 2. klucz celu do szyfrowania end-to-end (opcjonalnie)
    if (DIRECTORY_URL) {
        size_t s = onion::fetchNodes(DIRECTORY_URL, "service", services, 4);
        for (size_t i = 0; i < s; i++) {
            if (strcmp(services[i].name, DEST_NAME) == 0) {
                memcpy(destKey, services[i].x25519Pub, 32);
                haveDestKey = true;
            }
        }
    }
    Serial.printf("End-to-end encryption to the destination: %s\n", haveDestKey ? "on" : "off");

    onion::ClientConfig cfg;
    // cfg.hops           = 5;                          // 3..8 default 3
    // cfg.pathMode       = onion::PathMode::Ordered;   // kolejność z katalogu zamiast losowania
    // cfg.entry          = 0;                          // relay nr 0 z katalogu zawsze jako entry
    // cfg.exit           = 2;                          // relay nr 2 z katalogu zawsze jako exit
    // cfg.waitForReply   = false;                      // bez czekania na odpowiedź exita, default true
    // cfg.reuseCircuit   = true; cfg.circuitMaxUses = 10;
    // cfg.networkUp      = []() { return ETH.linkUp(); };   // przy łączu kablowym (#include <ETH.h>)

    if (!client.begin(relays, n, cfg)) {
        Serial.println("Client not started (need >= hops relays and valid config, see log)");
        return;
    }
    client.onResult(onResult);
}

// loop() to zwykłe zadanie FreeRTOS (rdzeń 1); tu tylko zleca wysyłkę, całą pracę robi zadanie klienta.
void loop() {
    const char* text = "hello world";
    uint32_t id = client.send(DEST_IP, DEST_PORT, text, strlen(text), haveDestKey ? destKey : nullptr);
    Serial.printf("queued message #%u\n", (unsigned)id);
    delay(15000);
}
