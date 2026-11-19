#include <WiFi.h>
#include <OnionClient.h>

const char* WIFI_SSID     = "iprivate-4";
const char* WIFI_PASSWORD = "Tciaszczyk1980";

// Cel wiadomości: 172.28.0.20:9000
const uint32_t DEST_IP   = onion::ipToU32(IPAddress(172, 28, 0, 20));
const uint16_t DEST_PORT = 9000;

// Domyślny katalog relayów. Używany tylko wtedy, gdy w NVS (pamięć flash ESP32 na ustawienia;
// namespace "relays", klucz "dir") nie ma zapisanego własnego katalogu w tym samym formacie JSON.
// Dzięki temu listę relayów można zmienić bez przeflashowywania programu (patrz README).
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
onion::Client client;

void onResult(bool ok) {
    Serial.println(ok ? "-> wysłano przez obwód" : "-> błąd wysyłki");
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

    size_t n = onion::loadRelaysFromNVS(relays);
    if (n == 0) n = onion::parseRelays(DEFAULT_RELAYS, relays);
    Serial.printf("Loaded %u relays\n", (unsigned)n);

    if (n < 3 || !client.begin(relays, 3)) {
        Serial.println("Need at least 3 relays, client not started");
        return;
    }
    client.onResult(onResult);
}

// loop() to zwykłe zadanie FreeRTOS (rdzeń 1); tu tylko zleca wysyłkę, całą pracę robi zadanie klienta.
void loop() {
    const char* text = "hello world";
    client.send(DEST_IP, DEST_PORT, text, strlen(text));
    delay(15000);
}
