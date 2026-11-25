// Klient: zadanie FreeRTOS, które jest właścicielem obwodu i obsługuje kolejkę wiadomości.
//
//   onion::Client client;
//   client.begin(directory, count);                       // domyślnie: 3 losowe hopy
//   uint32_t id = client.send(ip, port, "hello", 5);      // wraca od razu; praca dzieje się w zadaniu
//   // wynik i odpowiedź celu przychodzą do callbacku ustawionego przez onResult()
//
// Cały stan obwodu żyje wyłącznie w zadaniu klienta, więc nie potrzeba mutexów:
// inne zadania komunikują się z nim tylko przez kolejkę (send()).
#pragma once
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <freertos/queue.h>

#include "OnionCircuit.h"
#include "OnionRandom.h"
#include "OnionSeal.h"
#include "PathSelect.h"
#include "RelayDirectory.h"   // wygoda: jeden #include <OnionClient.h> w szkicu

namespace onion {

// Czy sieć działa (np. Ethernet). Zwraca false => wiadomość kończy się Failed bez prób łączenia.
using NetworkCheck = bool (*)();

struct ClientConfig {
    // --- ścieżka ---
    uint8_t  hops          = MIN_HOPS;          // MIN_HOPS..MAX_HOPS (3..8); katalog musi mieć co najmniej tyle relayów
    PathMode pathMode      = PathMode::Random;  // Random: nowa losowa ścieżka na obwód; Ordered: kolejność z katalogu
    int8_t   entry         = -1;                // indeks relaya z katalogu jako entry (-1 = wybiera pathMode)
    int8_t   exit          = -1;                // indeks relaya z katalogu jako exit  (-1 = wybiera pathMode)
    uint8_t  buildAttempts = 2;                 // ile razy próbować zbudować obwód (przy Random każda próba = nowa ścieżka)

    // --- obwód ---
    bool     reuseCircuit   = false;            // false: nowy obwód dla każdej wiadomości (jak w prototypie)
    uint16_t circuitMaxUses = 0;                // przy reuseCircuit: wymień obwód po tylu wiadomościach (0 = bez limitu)

    // --- wiadomości ---
    bool     waitForReply   = true;             // czekaj na odpowiedź exita (potwierdzenie + odpowiedź celu)
    uint32_t replyTimeoutMs = 20000;

    // --- sieć ---
    NetworkCheck networkUp  = nullptr;          // nullptr = bez sprawdzania; np. []{ return ETH.linkUp(); }

    // --- zadanie FreeRTOS ---
    uint32_t    stackBytes = 32768;             // TLS + X25519 potrzebują dużo stosu
    UBaseType_t priority   = 1;
    BaseType_t  core       = 1;                 // 1 = APP_CPU
    uint8_t     queueDepth = 4;
};

// Wynik jednej wiadomości. `response` (odpowiedź celu, po ewentualnym odszyfrowaniu e2e) jest
// ważna tylko wewnątrz callbacku; nullptr, gdy cel nic nie odpowiedział.
struct SendResult {
    uint32_t       seq;           // numer zwrócony przez send()
    SendStatus     status;
    const uint8_t* response;
    size_t         responseLen;
};

// Wywoływany w kontekście zadania klienta po każdej wiadomości. Trzymaj go krótkiego.
using ResultCallback = void (*)(const SendResult& result);

class Client {
public:
    // Kopiuje katalog (1..MAX_RELAYS relayów), sprawdza konfigurację i startuje zadanie.
    bool begin(const Relay* directory, size_t count, const ClientConfig& cfg = ClientConfig());

    // Nieblokujące. destPub (32 B, klucz celu z katalogu "service") włącza szyfrowanie end-to-end:
    // exit i relaye widzą tylko szyfrogram, a odpowiedź celu też jest szyfrowana.
    // Zwraca numer wiadomości (>0) albo 0 = nie przyjęto (kolejka pełna, klient nie wystartował
    // albo dane za duże: limit to maxPayload(hops), minus 48 B przy e2e).
    uint32_t send(uint32_t ip, uint16_t port, const void* data, size_t len,
                  const uint8_t* destPub = nullptr);

    void onResult(ResultCallback cb) { callback_ = cb; }

    // Najmniejszy dotąd zapas stosu zadania klienta w bajtach (do doboru stackBytes). 0 = nie wystartował.
    uint32_t stackFreeMin() const { return task_ ? uxTaskGetStackHighWaterMark(task_) : 0; }

private:
    struct Request {
        uint32_t seq;
        uint32_t ip;
        uint16_t port;
        uint16_t len;
        bool     sealed;                              // szyfrować e2e kluczem destPub
        uint8_t  destPub[PUB_SIZE];
        uint8_t  data[maxPayload(MIN_HOPS)];          // 416 B: tyle mieści się przy minimalnej liczbie hopów
    };

    static void taskEntry(void* self);
    void        run();
    void        process(const Request& req, uint8_t* respBuf, SendResult* result);
    bool        buildCircuit();

    Relay          dir_[MAX_RELAYS];
    size_t         count_ = 0;
    ClientConfig   cfg_;
    PathOptions    pathOpt_;
    Circuit        circuit_;
    uint16_t       uses_ = 0;
    uint32_t       seq_  = 0;
    QueueHandle_t  queue_    = nullptr;
    TaskHandle_t   task_     = nullptr;
    ResultCallback callback_ = nullptr;
};

}  // namespace onion
