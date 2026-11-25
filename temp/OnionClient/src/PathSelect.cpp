#include "PathSelect.h"
#include "OnionRandom.h"
#include "RelayDirectory.h"

namespace onion {

bool pathOptionsValid(size_t count, const PathOptions& o) {
    if (o.hops == 0 || o.hops > MAX_HOPS) return false;
    if (count < o.hops || count > MAX_RELAYS) return false;
    if (o.entry >= (int)count || o.exit >= (int)count) return false;
    if (o.entry >= 0 && o.exit >= 0 && (o.entry == o.exit || o.hops < 2)) return false;
    return true;
}

bool selectPath(const Relay* dir, size_t count, const PathOptions& o, Relay* out) {
    if (!pathOptionsValid(count, o)) return false;

    int8_t pick[MAX_HOPS];
    bool   used[MAX_RELAYS] = {false};
    for (uint8_t i = 0; i < o.hops; i++) pick[i] = -1;

    if (o.entry >= 0) { pick[0]          = o.entry; used[o.entry] = true; }
    if (o.exit  >= 0) { pick[o.hops - 1] = o.exit;  used[o.exit]  = true; }

    for (uint8_t i = 0; i < o.hops; i++) {
        if (pick[i] >= 0) continue;

        size_t freeCount = 0;
        for (size_t j = 0; j < count; j++) if (!used[j]) freeCount++;

        uint32_t k = 0;   // numer wolnego relaya, który bierzemy
        if (o.mode == PathMode::Random && !randomBelow((uint32_t)freeCount, &k)) return false;

        for (size_t j = 0; j < count; j++) {
            if (used[j]) continue;
            if (k-- == 0) { pick[i] = (int8_t)j; used[j] = true; break; }
        }
    }

    for (uint8_t i = 0; i < o.hops; i++) out[i] = dir[pick[i]];
    return true;
}

}  // namespace onion
