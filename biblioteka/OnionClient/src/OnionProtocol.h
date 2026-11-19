// Stałe i struktury protokołu: format komórki, nagłówek warstwy, rozmiary.
#pragma once
#include <Arduino.h>
#include <IPAddress.h>

namespace onion {

// Log biblioteki: domyślnie włączony, wyłączasz w czasie działania: onion::setLogging(false).
inline bool& loggingFlag() { static bool on = true; return on; }
inline void  setLogging(bool on) { loggingFlag() = on; }

}  // namespace onion

#ifndef ONION_LOG
#define ONION_LOG(fmt, ...) \
    do { if (onion::loggingFlag()) Serial.printf("[onion] " fmt "\n", ##__VA_ARGS__); } while (0)
#endif

namespace onion {

//Komórka (514 B, jak w Torze)

constexpr size_t CELL_SIZE         = 514;
constexpr size_t CELL_HEADER_SIZE  = 5;
constexpr size_t CELL_PAYLOAD_SIZE = CELL_SIZE - CELL_HEADER_SIZE;   // 509

// Polecenia komórki (jawne)
constexpr uint8_t CMD_CREATE  = 0x01;   // zbuduj pierwszy hop
constexpr uint8_t CMD_CREATED = 0x02;   // odpowiedź na CREATE
constexpr uint8_t CMD_RELAY   = 0x03;   // zaszyfrowany ładunek warstwowy
constexpr uint8_t CMD_DESTROY = 0x04;   // (na razie nieużywane)

struct __attribute__((packed)) Cell {
    uint32_t circuitId;
    uint8_t  command;
    uint8_t  payload[CELL_PAYLOAD_SIZE];
};
static_assert(sizeof(Cell) == CELL_SIZE, "Cell musi mieć 514 B");

//Warstwa RELAY (po odszyfrowaniu)

constexpr uint8_t RELAY_CMD_EXTEND   = 0x10;   // dodaj kolejny relay do obwodu
constexpr uint8_t RELAY_CMD_EXTENDED = 0x11;   // odpowiedź na EXTEND
constexpr uint8_t RELAY_CMD_DATA     = 0x12;   // przekaż dalej / dostarcz dane

struct __attribute__((packed)) RelayHeader {
    uint32_t ip;    
    uint16_t port;
    uint8_t  cmd;   
    uint16_t len;  
};
constexpr size_t RELAY_HEADER_SIZE = sizeof(RelayHeader);   // 9

//Rozmiary kryptograficzne

constexpr size_t IV_SIZE             = 16;
constexpr size_t KEY_SIZE            = 32;
constexpr size_t HANDSHAKE_PUB_SIZE  = 32;
constexpr size_t HMAC_SIZE           = 32;

//Obwód

constexpr uint8_t MAX_HOPS = 3;

//Każda warstwa dokłada IV + nagłówek, więc przy n hopach na dane zostaje:
//1 hop -> 484 B, 2 hopy -> 459 B, 3 hopy -> 434 B
constexpr size_t maxPayload(uint8_t hops) {
    return CELL_PAYLOAD_SIZE - hops * (IV_SIZE + RELAY_HEADER_SIZE);
}

//Katalog

struct Relay {
    uint32_t ip;               
    uint16_t port;
    uint8_t  x25519Pub[32]; 
    char     name[16];
};

inline uint32_t ipToU32(const IPAddress& ip) {
    return ((uint32_t)ip[0] << 24) | ((uint32_t)ip[1] << 16) |
           ((uint32_t)ip[2] << 8)  |  (uint32_t)ip[3];
}

inline IPAddress u32ToIp(uint32_t ip) {
    return IPAddress((ip >> 24) & 0xFF, (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, ip & 0xFF);
}

}  // namespace onion
