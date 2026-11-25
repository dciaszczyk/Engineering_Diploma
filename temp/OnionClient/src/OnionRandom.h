// Losowość dla całej biblioteki (klucze, IV, id obwodów, wybór ścieżki).
//
// esp_fill_random() jest prawdziwym TRNG tylko wtedy, gdy działa radio (WiFi/BT). Przy
// łączności kablowym (Ethernet, WiFi wyłączone) zwraca dane pseudolosowe. Dlatego:
//   1. własne źródło (setEntropySource), jeśli ustawione, np. zewnętrzny układ TRNG,
//   2. WiFi działa     -> esp_fill_random (TRNG),
//   3. WiFi nie działa -> bootloader_random_enable() na czas odczytu (TRNG z szumu ADC),
//   4. nic z powyższych -> randomBytes() zwraca false i nic nie generuje (kryptografia
//      nigdy nie dostaje przewidywalnych danych).
#pragma once
#include "OnionProtocol.h"

namespace onion {

enum class RngSource : uint8_t { None, RfTrng, BootloaderTrng, Custom };

using EntropyFn = bool (*)(uint8_t* buf, size_t len);

bool        randomBytes(void* buf, size_t len);
bool        randomBelow(uint32_t bound, uint32_t* out);   // równomiernie z [0, bound)

RngSource   rngSource();                                   // źródło, którego użyje następny odczyt
const char* rngSourceName(RngSource s);

void        setEntropySource(EntropyFn fn);                // nullptr = wróć do domyślnych
void        assumeRfActive(bool on);                       // np. gdy działa tylko BLE (nie wykrywamy go)

}  // namespace onion
