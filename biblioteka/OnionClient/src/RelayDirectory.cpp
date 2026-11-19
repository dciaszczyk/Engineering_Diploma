#include "RelayDirectory.h"
#include <ArduinoJson.h>
#include <Preferences.h>

namespace onion {
namespace {

bool hexToBytes(const char* hex, uint8_t* out, size_t len) {
    if (!hex || strlen(hex) != 2 * len) return false;
    for (size_t i = 0; i < len; i++) {
        char h[3] = {hex[2 * i], hex[2 * i + 1], 0};
        out[i] = (uint8_t)strtol(h, nullptr, 16);
    }
    return true;
}

}  // namespace

size_t parseRelays(const char* json, Relay* out, size_t maxCount) {
    StaticJsonDocument<4096> doc;
    if (deserializeJson(doc, json) != DeserializationError::Ok) {
        ONION_LOG("relay JSON parse failed");
        return 0;
    }

    size_t count = 0;
    for (JsonObject r : doc.as<JsonArray>()) {
        if (count >= maxCount) break;

        Relay&    relay = out[count];
        IPAddress ip;
        if (!ip.fromString(r["ip"] | "") || !hexToBytes(r["pub"] | "", relay.x25519Pub, 32)) {
            ONION_LOG("skipping invalid relay entry");
            continue;
        }
        relay.ip   = ipToU32(ip);
        relay.port = r["port"].as<uint16_t>();
        strlcpy(relay.name, r["name"] | "relay", sizeof(relay.name));
        count++;
    }
    return count;
}

size_t loadRelaysFromNVS(Relay* out, size_t maxCount, const char* ns, const char* key) {
    Preferences prefs;
    prefs.begin(ns, true);
    String json = prefs.getString(key, "");
    prefs.end();

    return json.length() ? parseRelays(json.c_str(), out, maxCount) : 0;
}

}  // namespace onion
