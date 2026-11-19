#include "OnionClient.h"
#include <WiFi.h>

namespace onion {

bool Client::begin(const Relay* path, uint8_t hops, const ClientConfig& cfg) {
    if (queue_ || hops == 0 || hops > MAX_HOPS) return false;   // już wystartował lub zły argument

    memcpy(path_, path, hops * sizeof(Relay));
    hops_ = hops;
    cfg_  = cfg;

    queue_ = xQueueCreate(cfg_.queueDepth, sizeof(Request));
    if (!queue_) return false;

    if (xTaskCreatePinnedToCore(taskEntry, "onion", cfg_.stackBytes, this,
                                cfg_.priority, nullptr, cfg_.core) != pdPASS) {
        vQueueDelete(queue_);
        queue_ = nullptr;
        return false;
    }
    return true;
}

bool Client::send(uint32_t ip, uint16_t port, const void* data, size_t len) {
    if (!queue_ || len > maxPayload(hops_)) return false;

    Request req;
    req.ip   = ip;
    req.port = port;
    req.len  = (uint16_t)len;
    memcpy(req.data, data, len);
    return xQueueSend(queue_, &req, 0) == pdTRUE;
}

void Client::taskEntry(void* self) {
    static_cast<Client*>(self)->run();
}

void Client::run() {
    Request req;
    for (;;) {
        xQueueReceive(queue_, &req, portMAX_DELAY);

        bool ok = handle(req);
        ONION_LOG("message to %s:%u %s", u32ToIp(req.ip).toString().c_str(), req.port,
                  ok ? "sent" : "FAILED");
        if (callback_) callback_(ok);
    }
}

bool Client::handle(const Request& req) {
    if (WiFi.status() != WL_CONNECTED) {
        ONION_LOG("WiFi down, dropping message");
        return false;
    }

    if (!cfg_.reuseCircuit || !circuit_.ready()) {
        if (!circuit_.build(path_, hops_)) return false;
    }

    bool ok = circuit_.send(req.ip, req.port, req.data, req.len);
    if (!ok || !cfg_.reuseCircuit) circuit_.reset();   // po błędzie następna wiadomość zbuduje obwód od nowa
    return ok;
}

}  // namespace onion
