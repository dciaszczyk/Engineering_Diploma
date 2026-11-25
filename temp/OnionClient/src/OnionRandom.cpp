#include "OnionRandom.h"
#include <esp_random.h>
#include <esp_wifi.h>
#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>

// bootloader_random.h jest dostępny tylko w części wersji rdzenia ESP32; bez niego
// fallback po kablu jest niedostępny (wtedy zostaje setEntropySource()).
#if __has_include(<bootloader_random.h>)
#include <bootloader_random.h>
#define ONION_HAVE_BOOTLOADER_RANDOM 1
#else
#define ONION_HAVE_BOOTLOADER_RANDOM 0
#endif

namespace onion {
namespace {

EntropyFn customFn  = nullptr;
bool      rfAssumed = false;

// Radio działa, gdy sterownik WiFi jest zainicjalizowany i nie jest w trybie NULL.
bool rfActive() {
    if (rfAssumed) return true;
    wifi_mode_t mode;
    return esp_wifi_get_mode(&mode) == ESP_OK && mode != WIFI_MODE_NULL;
}

#if ONION_HAVE_BOOTLOADER_RANDOM
// bootloader_random_enable/disable nie są wielobieżne.
SemaphoreHandle_t bootloaderLock() {
    static SemaphoreHandle_t m = xSemaphoreCreateMutex();
    return m;
}
#endif

}  // namespace

void setEntropySource(EntropyFn fn) { customFn = fn; }
void assumeRfActive(bool on)        { rfAssumed = on; }

RngSource rngSource() {
    if (customFn)    return RngSource::Custom;
    if (rfActive())  return RngSource::RfTrng;
#if ONION_HAVE_BOOTLOADER_RANDOM
    return RngSource::BootloaderTrng;
#else
    return RngSource::None;
#endif
}

const char* rngSourceName(RngSource s) {
    switch (s) {
        case RngSource::Custom:         return "custom entropy source";
        case RngSource::RfTrng:         return "hardware TRNG (RF active)";
        case RngSource::BootloaderTrng: return "hardware TRNG (bootloader_random, RF off)";
        default:                        return "NONE (no true entropy)";
    }
}

bool randomBytes(void* buf, size_t len) {
    if (len == 0) return true;

    switch (rngSource()) {
        case RngSource::Custom:
            return customFn((uint8_t*)buf, len);

        case RngSource::RfTrng:
            esp_fill_random(buf, len);
            return true;

        case RngSource::BootloaderTrng:
#if ONION_HAVE_BOOTLOADER_RANDOM
        {
            SemaphoreHandle_t m = bootloaderLock();
            xSemaphoreTake(m, portMAX_DELAY);
            bootloader_random_enable();        // szum z ADC jako źródło entropii
            esp_fill_random(buf, len);
            bootloader_random_disable();       // ADC wolne dla reszty programu
            xSemaphoreGive(m);
            return true;
        }
#endif
        default:
            break;
    }

    static bool warned = false;
    if (!warned) {
        warned = true;
        ONION_LOG("no true entropy source (WiFi off and bootloader_random unavailable); "
                  "refusing to generate random data. Use onion::setEntropySource().");
    }
    return false;
}

bool randomBelow(uint32_t bound, uint32_t* out) {
    if (bound == 0) return false;
    if (bound == 1) { *out = 0; return true; }

    const uint32_t limit = (0xFFFFFFFFu / bound) * bound;   // odrzucanie, żeby nie było obciążenia
    uint32_t r;
    do {
        if (!randomBytes(&r, sizeof(r))) return false;
    } while (r >= limit);
    *out = r % bound;
    return true;
}

}  // namespace onion
