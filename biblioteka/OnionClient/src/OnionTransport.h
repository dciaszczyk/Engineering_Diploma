// Transport: jedna komórka = jedno połączenie TLS do relaya.
#pragma once
#include "OnionProtocol.h"

namespace onion {

// Łączy się z relayem, wysyła `out`, a jeśli `reply` != nullptr, czeka na komórkę zwrotną.
// Połączenie jest zawsze zamykane na końcu.
bool exchangeCell(const Relay& relay, const Cell& out, Cell* reply = nullptr);

}  // namespace onion
