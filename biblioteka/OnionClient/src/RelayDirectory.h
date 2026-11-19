// Katalog relayów: parsowanie JSON-a i wczytywanie z NVS.
// Format: [{"name":"relay1","ip":"172.16.102.243","port":8001,"pub":"<64 znaki hex>"}, ...]
#pragma once
#include "OnionProtocol.h"

namespace onion {

constexpr size_t MAX_RELAYS = 8;

// Zwraca liczbę poprawnie wczytanych relayów (0 przy błędzie JSON-a).
size_t parseRelays(const char* json, Relay* out, size_t maxCount = MAX_RELAYS);

// Wczytuje JSON z NVS (domyślnie namespace "relays", klucz "dir"); 0 gdy brak lub błąd.
size_t loadRelaysFromNVS(Relay* out, size_t maxCount = MAX_RELAYS,
                         const char* ns = "relays", const char* key = "dir");

}  // namespace onion
