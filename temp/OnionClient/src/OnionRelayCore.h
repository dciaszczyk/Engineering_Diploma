// Logika relaya: tablica obwodów oraz obsługa komórek CREATE / RELAY (EXTEND, DATA) / DESTROY.
// Nie zależy od TLS ani od gniazd; dostaje kanał (Channel) i obsługuje na nim jedną komórkę.
//
// Jedno połączenie = jedna komórka (tak działają klient i relaye): serve() czyta komórkę,
// wysyła odpowiedź, jeśli jest, i wraca, a wywołujący zamyka połączenie.
#pragma once
#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>

#include "OnionChannel.h"
#include "OnionProtocol.h"

namespace onion {

constexpr size_t MAX_RELAY_CIRCUITS = 32;

// Czy ten relay (jako exit) może wysłać dane pod ip:port. nullptr = exit wyłączony.
// Uwaga: exit z polityką "wszystko" pozwala klientom sieci łączyć się z dowolnym hostem,
// także z Twoją siecią lokalną.
using ExitPolicy = bool (*)(uint32_t ip, uint16_t port);

struct RelayCoreConfig {
    ExitPolicy exitPolicy       = nullptr;
    uint8_t    maxCircuits      = 16;       // <= MAX_RELAY_CIRCUITS; przy braku miejsca wypada najstarszy
    uint32_t   circuitIdleMs    = 300000;   // obwód bez ruchu dłużej niż tyle wygasa
    uint32_t   readTimeoutMs    = 30000;    // czekanie na komórkę od klienta
    uint32_t   forwardTimeoutMs = 20000;    // czekanie na odpowiedź następnego hopa
    uint32_t   exitTimeoutMs    = 3000;     // jak długo exit zbiera odpowiedź celu (cel powinien zamknąć połączenie)
};

struct RelayStats {
    uint32_t created = 0, extended = 0, forwarded = 0, delivered = 0, deliveryFailed = 0,
             destroyed = 0, evicted = 0, rejected = 0, authFailed = 0;
};

class RelayCore {
public:
    bool begin(const uint8_t* staticPriv, const uint8_t* staticPub, const RelayCoreConfig& cfg);

    // Obsługuje jedną komórkę z kanału. Można wołać współbieżnie z kilku zadań.
    void serve(Channel& ch);

    RelayStats stats() const;
    size_t     activeCircuits() const;

private:
    struct CircuitEntry {
        bool     used;
        uint32_t id;               // id obwodu od poprzedniego hopa
        uint8_t  key[KEY_SIZE];    // klucz tego hopa
        uint8_t  depth;            // pozycja w obwodzie (0 = entry); wyznacza rozmiar warstwy
        bool     hasNext;
        uint32_t nextIp;
        uint16_t nextPort;
        uint32_t nextId;           // id tego samego obwodu na łączu do następnego hopa
        uint32_t lastMs;
    };

    // tablica obwodów (pod mutexem)
    bool lookup(uint32_t id, CircuitEntry* copy);
    void store(uint32_t id, const uint8_t* key, uint8_t depth);
    void setNext(uint32_t id, uint32_t ip, uint16_t port, uint32_t nextId);
    bool remove(uint32_t id, CircuitEntry* removed);
    void bump(uint32_t RelayStats::*field);

    // handlery
    void onCreate(Channel& ch, const Cell& in);
    void onRelay(Channel& ch, const Cell& in);
    void onDestroy(const Cell& in);
    void onForward(Channel& ch, uint32_t cid, const CircuitEntry& st, const uint8_t* nextLayer);
    void onExtend(Channel& ch, uint32_t cid, const CircuitEntry& st, const uint8_t* text);
    void onExit(Channel& ch, const Cell& in, const CircuitEntry& st, const uint8_t* text);

    // Odpowiedź z ostatniego hopa: text (layerSize(depth) - 28 B) szyfrowany kluczem hopa w stronę klienta.
    bool replyTerminal(Channel& ch, uint32_t cid, const CircuitEntry& st, const uint8_t* text);

    uint8_t         priv_[32];
    uint8_t         pub_[32];
    RelayCoreConfig cfg_;
    CircuitEntry    table_[MAX_RELAY_CIRCUITS];
    RelayStats      stats_;
    SemaphoreHandle_t mu_ = nullptr;
};

}  // namespace onion
