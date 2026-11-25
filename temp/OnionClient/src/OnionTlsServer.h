// Serwer TLS (mbedTLS) dla relaya: obsługuje jedno przyjęte gniazdo.
// Wymaga mbedTLS skonfigurowanego jako "Server & Client" (domyślne w ESP-IDF).
#pragma once
#include "OnionRelayCore.h"

namespace onion {

class TlsServer {
public:
    ~TlsServer();

    // certPem/keyPem: certyfikat i klucz serwera w PEM (zakończone zerem). Klienci i tak go nie
    // weryfikują (setInsecure), ale TLS wymaga certyfikatu.
    bool begin(const char* certPem, const char* keyPem);

    // Robi handshake TLS na gnieździe `fd`, daje kanał do core.serve(), zamyka TLS i gniazdo.
    void handle(int fd, RelayCore& core);

private:
    struct Impl;
    Impl* impl_ = nullptr;
};

}  // namespace onion
