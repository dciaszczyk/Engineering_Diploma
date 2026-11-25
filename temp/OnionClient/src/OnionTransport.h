// Transport: jedna komórka = jedno połączenie TLS do relaya; zwykłe TCP do celu (exit).
#pragma once
#include "OnionProtocol.h"

namespace onion {

// Łączy się z relayem przez TLS, wysyła `out`, a jeśli `reply` != nullptr, czeka do `replyTimeoutMs`
// na komórkę zwrotną. Połączenie jest zawsze zamykane na końcu. false = błąd lub timeout.
bool exchangeCell(const Relay& relay, const Cell& out, Cell* reply = nullptr,
                  uint32_t replyTimeoutMs = 10000);

// Zwykłe TCP (bez TLS), używane przez exit: łączy się z ip:port, wysyła `req`, potem zbiera
// odpowiedź do EOF, `cap` bajtów albo `timeoutMs`. *respLen = ile bajtów odpowiedzi.
// false tylko gdy nie udało się połączyć lub wysłać (pusta odpowiedź też jest sukcesem).
bool tcpExchange(uint32_t ip, uint16_t port, const uint8_t* req, size_t len,
                 uint8_t* resp, size_t cap, size_t* respLen, uint32_t timeoutMs = 3000);

}  // namespace onion
