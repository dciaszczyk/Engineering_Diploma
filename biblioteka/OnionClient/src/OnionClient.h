// Klient: zadanie FreeRTOS, które jest właścicielem obwodu i obsługuje kolejkę wiadomości.
//
//   onion::Client client;
//   client.begin(relays, 3);
//   client.send(ip, port, "hello", 5);     // wraca od razu; praca dzieje się w zadaniu
//
// inne zadania komunikują się z nim tylko przez kolejkę (send()).
#pragma once
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <freertos/queue.h>

#include "OnionCircuit.h"
#include "RelayDirectory.h"  

namespace onion {

struct ClientConfig {
    bool        reuseCircuit = false;   // false: nowy obwód dla każdej wiadomości. true: ponowne wykorzystanie obwodu
    uint32_t    stackBytes   = 32768;   // TLS + X25519+wifi był overflow
    UBaseType_t priority     = 1;
    BaseType_t  core         = 1;       // 1 = APP_CPU
    uint8_t     queueDepth   = 4;
};

using ResultCallback = void (*)(bool ok);

class Client {
public:
    // Kopiuje ścieżkę (1..MAX_HOPS relayów, entry relay pierwszy) i startuje zadanie.
    bool begin(const Relay* path, uint8_t hops, const ClientConfig& cfg = ClientConfig());

    // (limit: maxPayload(hops), czyli 434 B dla 3 hopów).
    bool send(uint32_t ip, uint16_t port, const void* data, size_t len);

    void onResult(ResultCallback cb) { callback_ = cb; }

private:
    struct Request {
        uint32_t ip;
        uint16_t port;
        uint16_t len;
        uint8_t  data[maxPayload(1)];
    };

    static void taskEntry(void* self);
    void        run();
    bool        handle(const Request& req);

    Relay          path_[MAX_HOPS];
    uint8_t        hops_ = 0;
    ClientConfig   cfg_;
    Circuit        circuit_;
    QueueHandle_t  queue_    = nullptr;
    ResultCallback callback_ = nullptr;
};

}  // namespace onion
