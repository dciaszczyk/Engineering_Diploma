// Obwód: ścieżka relayów + klucze hopów, oraz polecenia protokołu CREATE / EXTEND / DATA.
// Klasa nie jest thread-safe: używaj jej z jednego zadania (robi to onion::Client).
#pragma once
#include "OnionProtocol.h"

namespace onion {

class Circuit {
public:
    // CREATE do path[0], potem EXTEND do kolejnych. Przy błędzie obwód jest czyszczony.
    bool build(const Relay* path, uint8_t hops);

    // Wysyła dane do ip:port przez cały obwód (komenda DATA, bez odpowiedzi).
    bool send(uint32_t ip, uint16_t port, const uint8_t* data, size_t len);

    void    reset();
    bool    ready() const { return hops_ > 0; }
    uint8_t hops()  const { return hops_; }

private:
    bool   create(const Relay& first);
    bool   extend(const Relay& next);

    // Zawija (cmd, ip:port, payload) w warstwy dla wszystkich hopów i wysyła jako RELAY do entry relaya.
    bool   sendRelay(uint8_t cmd, uint32_t ip, uint16_t port,
                     const uint8_t* payload, size_t len, Cell* reply) const;
    size_t wrapOnion(uint8_t cmd, uint32_t ip, uint16_t port,
                     const uint8_t* payload, size_t len, uint8_t* out) const;

    // Zdejmuje warstwy odpowiedzi kluczami hopów 0..n-1.
    size_t unwrap(const uint8_t* in, size_t len, uint8_t* out) const;

    uint32_t id_   = 0;
    uint8_t  hops_ = 0;
    Relay    path_[MAX_HOPS];
    uint8_t  keys_[MAX_HOPS][KEY_SIZE];
};

}  // namespace onion
