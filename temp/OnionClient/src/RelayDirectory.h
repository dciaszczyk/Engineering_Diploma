// Katalog relayów: parsowanie JSON-a i wczytywanie z NVS.
// Format: [{"name":"relay1","ip":"172.16.102.243","port":8001,"pub":"<64 znaki hex>"}, ...]
#pragma once
#include "OnionProtocol.h"

namespace onion {

constexpr size_t MAX_RELAYS = 16;

// Zwraca liczbę poprawnie wczytanych relayów (0 przy błędzie JSON-a).
size_t parseRelays(const char* json, Relay* out, size_t maxCount = MAX_RELAYS);

// Wczytuje JSON z NVS (domyślnie namespace "relays", klucz "dir"); 0 gdy brak lub błąd.
size_t loadRelaysFromNVS(Relay* out, size_t maxCount = MAX_RELAYS,
                         const char* ns = "relays", const char* key = "dir");

// Pobiera z katalogu (miniserwer extras/python/directory.py, adres np. "http://192.168.1.10:8080")
// listę węzłów w wersji protokołu tej biblioteki: kind = "relay" (relaye) albo "service" (cele
// z kluczem do szyfrowania end-to-end). Zwraca liczbę wczytanych wpisów (0 przy błędzie).
// Katalog jest zaufany (prototyp), a połączenie to zwykłe HTTP.
size_t fetchNodes(const char* baseUrl, const char* kind, Relay* out, size_t maxCount = MAX_RELAYS);

// Rejestruje węzeł w katalogu: nazwa (bez cudzysłowów), port i klucz publiczny (64 znaki hex).
// Adres IP ustala sam katalog z połączenia. true = katalog przyjął wpis (HTTP 200).
bool registerNode(const char* baseUrl, const char* kind, const char* name, uint16_t port, const char* pubHex);

}  // namespace onion
