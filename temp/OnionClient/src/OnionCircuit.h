// Obwód klienta: klucze hopów + adres entry relaya oraz polecenia CREATE / EXTEND / DATA / DESTROY.
// Klasa nie jest thread-safe: używaj jej z jednego zadania (robi to onion::Client).
#pragma once
#include "OnionProtocol.h"

namespace onion {

// Odpowiedź celu odebrana przez obwód. buf (min. maxResponse(hops) B) dostarcza wywołujący.
struct Response {
    uint8_t* buf;
    size_t   cap;
    size_t   len = 0;    // ile bajtów odpowiedzi trafiło do buf
};

class Circuit {
public:
    // Buduje obwód: CREATE do path[0], potem EXTEND do kolejnych. Przy błędzie czyści stan i
    // (jeśli coś zdążyło powstać) niszczy częściowy obwód na relayach.
    bool build(const Relay* path, uint8_t hops);

    // Wysyła `data` do ip:port przez cały obwód (polecenie DATA).
    //   reply != nullptr: czeka do timeoutMs na odpowiedź exita i wypełnia *reply.
    //                     Wynik: Delivered, ExitFailed, NoAck albo Mismatch.
    //   reply == nullptr: wysyła bez czekania (Sent albo Failed).
    // Integralność każdej warstwy sprawdzają hopy (AES-GCM); odpowiedź jest związana z tą wiadomością.
    SendStatus send(uint32_t ip, uint16_t port, const uint8_t* data, size_t len,
                    Response* reply, uint32_t timeoutMs = 20000);

    // DESTROY do entry relaya (relaye propagują go dalej po obwodzie), potem czyści stan lokalny.
    void    destroy();

    // Czyści tylko stan lokalny, bez informowania relayów.
    void    reset();
    bool    ready() const { return hops_ > 0; }
    uint8_t hops()  const { return hops_; }

private:
    bool create(const Relay& first);
    bool extend(const Relay& next);

    // Zawija tekst końcowy (terminalSize(hops_) B) w warstwy wszystkich hopów, od ostatniego do entry.
    // out: CELL_PAYLOAD_SIZE B. innerNonce (opcjonalnie): nonce najgłębszej warstwy, którego exit
    // używa do powiązania odpowiedzi z wiadomością.
    bool wrap(const uint8_t* terminal, uint8_t* out, uint8_t* innerNonce) const;

    // Zdejmuje warstwy odpowiedzi kluczami hopów 0..n-1; false = któraś warstwa zmieniona.
    bool unwrap(const uint8_t* payload, uint8_t* terminalOut) const;

    // Wysyła tekst końcowy przez obwód do entry relaya i (gdy reply != nullptr) czeka na odpowiedź.
    bool exchange(const uint8_t* terminal, Cell* reply, uint32_t timeoutMs, uint8_t* innerNonce) const;

    uint32_t id_   = 0;
    uint8_t  hops_ = 0;
    Relay    entry_;
    uint8_t  keys_[MAX_HOPS][KEY_SIZE];
};

}  // namespace onion
