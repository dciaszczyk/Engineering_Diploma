// Relay na ESP32. Klient dodaje go do swojego katalogu z kluczem wypisanym przy starcie.
#include <WiFi.h>
#include <OnionRelay.h>

const char* WIFI_SSID     = "iprivate-4";
const char* WIFI_PASSWORD = "Tciaszczyk1980";

// Katalog (extras/python/directory.py): relay sam wrzuca tam swoją nazwę, port i klucz publiczny po
// starcie i odświeża wpis co minutę. nullptr = bez katalogu.
const char* DIRECTORY_URL = "http://172.28.0.2:8080";

// Klienci tej biblioteki nie weryfikują certyfikatów relayów, ale TLS wymaga jakiegoś. Własne wygenerujesz tak:
//   openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout key.pem -out cert.pem -days 3650 -subj "/CN=onion-relay"
const char* CERT_PEM = R"PEM(
-----BEGIN CERTIFICATE-----
MIIBjTCCATOgAwIBAgIUcnOMkrrVVcdCBG95k1FuCh+CX0owCgYIKoZIzj0EAwIw
GzEZMBcGA1UEAwwQb25pb24tcmVsYXktZGVtbzAgFw0yNjExMjIxNjM2NDBaGA8y
MTI2MTAyOTE2MzY0MFowGzEZMBcGA1UEAwwQb25pb24tcmVsYXktZGVtbzBZMBMG
ByqGSM49AgEGCCqGSM49AwEHA0IABG/tXj226ldSPAlDFJlYZ06kotBhpYlsOu+6
pj/LcexY3OGDJEYM+8+2arhWoeCoORYM+it0h3eWbKcHluaMIeOjUzBRMB0GA1Ud
DgQWBBSTmU2pe+pOgp9aRrdCY2Gdq8nrTzAfBgNVHSMEGDAWgBSTmU2pe+pOgp9a
RrdCY2Gdq8nrTzAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0gAMEUCIQDq
wQLU66LZGCEFZkrtC0Xq8lPiTI1UdU9RITpfrxOfwQIgOsCoXlkOD/2sLS+OkJRg
kRXHG6fT58D7rYi0bQbmHt4=
-----END CERTIFICATE-----
)PEM";

const char* KEY_PEM = R"PEM(
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgPqxqEwH+k2LpCqum
j+9fbO+syFBDkdGjqWYwyS9xrr2hRANCAARv7V49tupXUjwJQxSZWGdOpKLQYaWJ
bDrvuqY/y3HsWNzhgyRGDPvPtmq4VqHgqDkWDPordId3lmynB5bmjCHj
-----END PRIVATE KEY-----
)PEM";

// Polityka exita: ten relay dostarcza dane TYLKO pod wskazany adres. Zwracając true dla wszystkiego
// pozwolisz klientom sieci łączyć się z dowolnym hostem.
// Bez exitPolicy (nullptr) relay działa wyłącznie jako entry/środkowy hop.
static bool allowExit(uint32_t ip, uint16_t port) {
    return ip == onion::ipToU32(IPAddress(172, 28, 0, 20)) && port == 9000;
}

onion::RelayNode node;

void setup() {
    Serial.begin(115200);
    delay(200);

    WiFi.mode(WIFI_STA);
    WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
    while (WiFi.status() != WL_CONNECTED) {
        delay(500);
        Serial.print('.');
    }
    Serial.printf("\nConnected, IP=%s\n", WiFi.localIP().toString().c_str());

    // Przy łączu kablowym (WiFi wyłączone) biblioteka sama przełączy się na TRNG z bootloader_random.
    // Gdyby nie był dostępny, podaj własne źródło: onion::setEntropySource(myTrng);

    onion::RelayConfig cfg;
    cfg.port       = 8001;
    cfg.certPem    = CERT_PEM;
    cfg.keyPem     = KEY_PEM;
    cfg.exitPolicy = allowExit;
    cfg.directoryUrl = DIRECTORY_URL;
    cfg.name         = "esp32-relay";
    // cfg.workers = 2;            // więcej równoległych połączeń kosztem pamięci (ok. 40-80 KB każdy)

    if (!node.begin(cfg)) {
        Serial.println("Relay start failed (see log)");
        return;
    }
    // Z katalogiem klucz trafia do klientów sam; bez katalogu wpisz go jako "pub" tego relaya ręcznie.
    Serial.printf("Relay up. static pub: %s\n", node.publicKeyHex());
}

void loop() {
    onion::RelayStats s = node.stats();
    Serial.printf("circuits=%u created=%u extended=%u forwarded=%u delivered=%u destroyed=%u rejected=%u heap=%u\n",
                  (unsigned)node.activeCircuits(), (unsigned)s.created, (unsigned)s.extended,
                  (unsigned)s.forwarded, (unsigned)s.delivered, (unsigned)s.destroyed,
                  (unsigned)s.rejected, (unsigned)ESP.getFreeHeap());
    delay(30000);
}
