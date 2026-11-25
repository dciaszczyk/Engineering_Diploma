// Statyczny klucz tożsamości relaya (X25519). Jego część publiczna idzie do katalogów
// klientów jako "pub"; prywatna zostaje w NVS urządzenia.
//
// Uwaga: NVS jest domyślnie nieszyfrowany. Na produkcji włącz szyfrowanie NVS/flash.
#pragma once
#include "OnionProtocol.h"

namespace onion {

struct RelayIdentity {
    uint8_t priv[32];
    uint8_t pub[32];
};

// Wczytuje tożsamość z NVS albo generuje nową i zapisuje (pierwszy start).
// false = błąd NVS albo brak entropii (patrz OnionRandom.h).
bool loadOrCreateIdentity(RelayIdentity& id, const char* nvsNamespace = "onion");

// Usuwa zapisaną tożsamość; następny start wygeneruje nową (zmieni się "pub" w katalogach klientów!).
bool eraseIdentity(const char* nvsNamespace = "onion");

void pubToHex(const uint8_t* pub, char out[65]);

}  // namespace onion
