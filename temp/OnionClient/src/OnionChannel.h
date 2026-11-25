// Abstrakcyjny kanał bajtowy (połączenie od klienta lub poprzedniego relaya).
// Dzięki niemu logika relaya (OnionRelayCore) nie zależy od TLS ani od gniazd.
#pragma once
#include <stddef.h>
#include <stdint.h>

namespace onion {

class Channel {
public:
    virtual ~Channel() {}
    virtual bool read(void* buf, size_t len, uint32_t timeoutMs) = 0;   // dokładnie len bajtów
    virtual bool write(const void* buf, size_t len) = 0;
};

}  // namespace onion
