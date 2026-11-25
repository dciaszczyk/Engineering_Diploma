#include "RelayIdentity.h"
#include "OnionCrypto.h"
#include <Preferences.h>

namespace onion {

bool loadOrCreateIdentity(RelayIdentity& id, const char* nvsNamespace) {
    Preferences prefs;
    if (!prefs.begin(nvsNamespace, false)) {
        ONION_LOG("identity: NVS open failed");
        return false;
    }

    bool ok = false;
    if (prefs.getBytesLength("relay_id") == sizeof(RelayIdentity)) {
        ok = prefs.getBytes("relay_id", &id, sizeof(id)) == sizeof(id);
    } else {
        if (generateKeypair(id.priv, id.pub)) {
            ok = prefs.putBytes("relay_id", &id, sizeof(id)) == sizeof(id);
            if (ok) ONION_LOG("identity: generated new relay key");
        }
    }
    prefs.end();
    return ok;
}

bool eraseIdentity(const char* nvsNamespace) {
    Preferences prefs;
    if (!prefs.begin(nvsNamespace, false)) return false;
    bool ok = prefs.remove("relay_id");
    prefs.end();
    return ok;
}

void pubToHex(const uint8_t* pub, char out[65]) {
    static const char* hex = "0123456789abcdef";
    for (int i = 0; i < 32; i++) {
        out[2 * i]     = hex[pub[i] >> 4];
        out[2 * i + 1] = hex[pub[i] & 15];
    }
    out[64] = 0;
}

}  // namespace onion
