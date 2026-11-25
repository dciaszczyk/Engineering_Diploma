// Węzeł relay na ESP32: serwer TLS, tablica obwodów, tożsamość w NVS, zadania FreeRTOS.
//
//   onion::RelayNode node;
//   onion::RelayConfig cfg;
//   cfg.port = 8001; cfg.certPem = CERT; cfg.keyPem = KEY;
//   node.begin(cfg);
//   Serial.println(node.publicKeyHex());     // wpisz to jako "pub" w katalogach klientów
//
// Działa na dowolnym interfejsie lwIP (WiFi lub Ethernet). Pamięć: jeden TLS to ok. 40 KB
// sterty, a worker przekazujący dalej trzyma dwa naraz (przychodzący i wychodzący).
#pragma once
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <freertos/queue.h>

#include "OnionRandom.h"
#include "OnionRelayCore.h"
#include "OnionTlsServer.h"
#include "RelayDirectory.h"
#include "RelayIdentity.h"

namespace onion {

struct RelayConfig {
    // --- sieć / TLS ---
    uint16_t    port    = 8001;
    const char* certPem = nullptr;      // certyfikat serwera TLS (PEM); wskaźnik musi przeżyć działanie relaya
    const char* keyPem  = nullptr;      // klucz prywatny serwera TLS (PEM)

    // --- exit ---
    ExitPolicy  exitPolicy = nullptr;   // nullptr = ten relay nie dostarcza danych do celów (nie jest exitem)
    uint32_t    exitTimeoutMs = 3000;   // jak długo exit zbiera odpowiedź celu (cel powinien zamknąć połączenie)

    // --- katalog (opcjonalnie) ---
    const char* directoryUrl = nullptr; // np. "http://192.168.1.10:8080": relay sam się rejestruje po starcie
    const char* name         = "esp32-relay";             // nazwa w katalogu (bez cudzysłowów)
    uint32_t    registerIntervalMs = 60000;               // jak często odświeżać wpis

    // --- obwody ---
    uint8_t     maxCircuits      = 16;      // <= MAX_RELAY_CIRCUITS
    uint32_t    circuitIdleMs    = 300000;  // obwód bez ruchu wygasa po tylu ms
    uint32_t    forwardTimeoutMs = 20000;   // czekanie na odpowiedź następnego hopa

    // --- zadania FreeRTOS ---
    uint8_t     workers    = 1;         // równoległe połączenia; każdy to ok. 40-80 KB sterty
    uint32_t    stackBytes = 32768;
    UBaseType_t priority   = 1;
    BaseType_t  core       = 1;
    uint8_t     backlog    = 4;         // ile przyjętych połączeń może czekać na workera

    // --- tożsamość ---
    const char* nvsNamespace = "onion";
};

class RelayNode {
public:
    bool begin(const RelayConfig& cfg);

    const uint8_t* publicKey()    const { return id_.pub; }   // 32 B
    const char*    publicKeyHex() const { return pubHex_; }   // 64 znaki, do katalogu klientów

    RelayStats stats() const          { return core_.stats(); }
    size_t     activeCircuits() const { return core_.activeCircuits(); }

private:
    static void acceptEntry(void* self);
    static void workerEntry(void* self);
    static void registerEntry(void* self);
    void        acceptLoop();
    void        workerLoop();
    void        registerLoop();   // rejestruje relay w katalogu i odświeża wpis

    RelayConfig   cfg_;
    RelayIdentity id_;
    char          pubHex_[65] = {0};
    RelayCore     core_;
    TlsServer     tls_;
    int           listenFd_ = -1;
    QueueHandle_t conns_    = nullptr;
};

}  // namespace onion
