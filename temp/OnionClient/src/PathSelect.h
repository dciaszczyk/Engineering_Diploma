// Dobór ścieżki (entry -> ... -> exit) z katalogu relayów.
#pragma once
#include "OnionProtocol.h"

namespace onion {

enum class PathMode : uint8_t {
    Ordered,   // kolejność z katalogu (pierwsze wolne relaye)
    Random,    // losowo, bez powtórzeń (TRNG), nowa ścieżka przy każdym obwodzie
};

struct PathOptions {
    uint8_t  hops  = MIN_HOPS;
    PathMode mode  = PathMode::Random;
    int8_t   entry = -1;   // indeks relaya w katalogu użytego jako entry; -1 = wybiera `mode`
    int8_t   exit  = -1;   // indeks relaya użytego jako exit;             -1 = wybiera `mode`
};

// Czy opcje mają sens dla katalogu o `count` relayach (bez losowania).
bool pathOptionsValid(size_t count, const PathOptions& opt);

// Wybiera opt.hops różnych relayów. entry/exit (jeśli ustawione) zajmują pierwszą/ostatnią
// pozycję, reszta według `mode`. false = złe opcje albo brak entropii.
bool selectPath(const Relay* dir, size_t count, const PathOptions& opt, Relay* out);

}  // namespace onion
