// Stałe i struktury protokołu v3: format komórki, rozmiary warstw, polecenia, wynik wysyłki.
// Pełny opis formatu (z diagramem) jest w extras/python/onion_common.py, a skrót w README.
#pragma once
#include <Arduino.h>
#include <IPAddress.h>

namespace onion {

// Log biblioteki: domyślnie włączony, wyłączasz w czasie działania: onion::setLogging(false).
inline bool& loggingFlag() { static bool on = true; return on; }
inline void  setLogging(bool on) { loggingFlag() = on; }

}  // namespace onion

// Własny ONION_LOG zadziała tylko jako flaga kompilacji (-D), bo #define w szkicu
// nie jest widoczny dla plików .cpp biblioteki.
#ifndef ONION_LOG
#define ONION_LOG(fmt, ...) \
    do { if (onion::loggingFlag()) Serial.printf("[onion] " fmt "\n", ##__VA_ARGS__); } while (0)
#endif

namespace onion {

// ---- Wersja ----------------------------------------------------------------

// Numer wersji idzie w każdym CREATE/EXTEND i wchodzi do HKDF, więc relay o innej wersji
// odrzuca obwód (odpowiada DESTROY z własną wersją), a klucze różnych wersji się nie zgadzają.
constexpr uint8_t PROTO_VERSION = 3;

// ---- Komórka (514 B, jak w Torze) ------------------------------------------

constexpr size_t CELL_SIZE         = 514;
constexpr size_t CELL_HEADER_SIZE  = 5;
constexpr size_t CELL_PAYLOAD_SIZE = CELL_SIZE - CELL_HEADER_SIZE;   // 509

constexpr uint8_t CMD_CREATE  = 0x01;   // zbuduj pierwszy hop:   wersja | głębokość | E
constexpr uint8_t CMD_CREATED = 0x02;   // odpowiedź na CREATE:   R | MAC
constexpr uint8_t CMD_RELAY   = 0x03;   // warstwa AES-GCM (patrz layerSize) + losowe dopełnienie
constexpr uint8_t CMD_DESTROY = 0x04;   // zamknij obwód; jako odpowiedź na CREATE: payload[0] = wersja relaya

struct __attribute__((packed)) Cell {
    uint32_t circuitId;
    uint8_t  command;
    uint8_t  payload[CELL_PAYLOAD_SIZE];
};
static_assert(sizeof(Cell) == CELL_SIZE, "Cell musi mieć 514 B");

// ---- Rozmiary kryptograficzne ----------------------------------------------

constexpr size_t NONCE_SIZE     = 12;
constexpr size_t TAG_SIZE       = 16;
constexpr size_t LAYER_OVERHEAD = NONCE_SIZE + TAG_SIZE;   // 28 B na warstwę
constexpr size_t KEY_SIZE       = 32;
constexpr size_t PUB_SIZE       = 32;
constexpr size_t HMAC_SIZE      = 32;

constexpr uint8_t DIR_FORWARD  = 0;   // AAD warstwy w stronę celu
constexpr uint8_t DIR_BACKWARD = 1;   // AAD warstwy w stronę klienta

// ---- Warstwy ---------------------------------------------------------------
//
// Warstwa = nonce(12) | szyfrogram | tag(16). Każdy hop dokłada (w stronę klienta) albo zdejmuje
// (w stronę celu) 28 B, więc rozmiar warstwy zależy wyłącznie od głębokości hopa d (0 = entry):
//     layerSize(d) = 509 - 28*d
// Relay zna swoją głębokość (dostaje ją w CREATE), więc nie potrzeba pól długości, a komórki mają
// stały rozmiar. Warstwa hopa, który ma następny hop, to cała warstwa następnego hopa (bez adresów:
// przekazywanie idzie po circuit id). Dopiero ostatni hop widzi polecenie ("tekst końcowy").

constexpr size_t layerSize(uint8_t depth)   { return CELL_PAYLOAD_SIZE - depth * LAYER_OVERHEAD; }
constexpr size_t terminalSize(uint8_t hops) { return layerSize(hops - 1) - LAYER_OVERHEAD; }   // 509 - 28*hops

// Polecenia w tekście końcowym (pierwszy bajt):
constexpr uint8_t T_EXTEND     = 0x10;   // ip(4) port(2) wersja(1) E(32)
constexpr uint8_t T_EXTENDED   = 0x11;   // R(32) MAC(32)
constexpr uint8_t T_DATA       = 0x12;   // ip(4) port(2) długość(2) dane
constexpr uint8_t T_DATA_REPLY = 0x13;   // status(1) nonce_żądania(12) długość(2) odpowiedź

constexpr size_t  DATA_HEADER_SIZE  = 9;    // T_DATA + ip + port + długość
constexpr size_t  REPLY_HEADER_SIZE = 16;   // T_DATA_REPLY + status + nonce + długość
constexpr size_t  EXTEND_BODY_SIZE  = 40;   // T_EXTEND + ip + port + wersja + E

constexpr uint8_t STATUS_OK     = 0;   // exit dostarczył dane do celu
constexpr uint8_t STATUS_FAILED = 1;   // exit nie mógł dostarczyć (polityka, brak połączenia)

constexpr uint8_t MIN_HOPS = 3;   // najmniej, na jakie pozwala onion::Client
constexpr uint8_t MAX_HOPS = 8;

// Ile bajtów danych mieści jedna wiadomość i jedna odpowiedź przy `hops` hopach:
//   3 hopy: 416 B / 409 B,   5 hopów: 360 B / 353 B,   8 hopów: 276 B / 269 B.
// Szyfrowanie end-to-end do celu zabiera z tego jeszcze 48 B (żądanie) i 16 B (odpowiedź).
constexpr size_t maxPayload(uint8_t hops)  { return terminalSize(hops) - DATA_HEADER_SIZE; }
constexpr size_t maxResponse(uint8_t hops) { return terminalSize(hops) - REPLY_HEADER_SIZE; }

// ---- Katalog ---------------------------------------------------------------

struct Relay {
    uint32_t ip;               // 172.28.0.12 -> 0xAC1C000C
    uint16_t port;
    uint8_t  x25519Pub[32];    // statyczny klucz tożsamości relaya; w handshake uwierzytelnia relay
    char     name[16];
};

inline uint32_t ipToU32(const IPAddress& ip) {
    return ((uint32_t)ip[0] << 24) | ((uint32_t)ip[1] << 16) |
           ((uint32_t)ip[2] << 8)  |  (uint32_t)ip[3];
}

inline IPAddress u32ToIp(uint32_t ip) {
    return IPAddress((ip >> 24) & 0xFF, (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, ip & 0xFF);
}

// ---- Wynik wysyłki ---------------------------------------------------------

enum class SendStatus : uint8_t {
    Delivered,    // exit potwierdził dostarczenie, odpowiedź (jeśli była) przeszła weryfikację
    Sent,         // wysłano do obwodu, bez czekania na odpowiedź (verifyDelivery = false)
    ExitFailed,   // odpowiedź poprawna, ale exit nie dostarczył danych do celu
    NoCircuit,    // nie udało się zbudować obwodu
    NoAck,        // brak odpowiedzi (timeout, zerwane łącze, warstwa odrzucona przez któryś hop)
    Mismatch,     // odpowiedź nie przeszła weryfikacji (zmieniona warstwa, obca wiadomość, zły tag e2e)
    Failed,       // błąd lokalny / transportu (tryb bez weryfikacji)
};

inline const char* statusName(SendStatus s) {
    switch (s) {
        case SendStatus::Delivered:  return "delivered";
        case SendStatus::Sent:       return "sent (no reply awaited)";
        case SendStatus::ExitFailed: return "exit failed";
        case SendStatus::NoCircuit:  return "no circuit";
        case SendStatus::NoAck:      return "no reply";
        case SendStatus::Mismatch:   return "MISMATCH";
        default:                     return "failed";
    }
}

}  // namespace onion
