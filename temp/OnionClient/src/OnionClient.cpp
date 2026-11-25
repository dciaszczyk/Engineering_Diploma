#include "OnionClient.h"

namespace onion {

namespace {

// Loguje wybraną ścieżkę, np. "path: relay2 > relay1 > relay3".
void logPath(const Relay* path, uint8_t hops) {
    char buf[MAX_HOPS * (sizeof(Relay::name) + 3) + 1];
    size_t pos = 0;
    buf[0] = 0;
    for (uint8_t i = 0; i < hops && pos < sizeof(buf); i++)
        pos += snprintf(buf + pos, sizeof(buf) - pos, "%s%s", i ? " > " : "", path[i].name);
    ONION_LOG("path: %s", buf);
}

}  // namespace

// ---- Start i wysyłanie -----------------------------------------------------

bool Client::begin(const Relay* directory, size_t count, const ClientConfig& cfg) {
    if (queue_) return false;   // już wystartował

    if (cfg.hops < MIN_HOPS || cfg.hops > MAX_HOPS) {
        ONION_LOG("config: hops must be %u..%u", (unsigned)MIN_HOPS, (unsigned)MAX_HOPS);
        return false;
    }
    PathOptions opt;
    opt.hops  = cfg.hops;
    opt.mode  = cfg.pathMode;
    opt.entry = cfg.entry;
    opt.exit  = cfg.exit;
    if (!pathOptionsValid(count, opt)) {
        ONION_LOG("config: need >= %u distinct relays (have %u, max %u) and valid entry/exit indices",
                  (unsigned)cfg.hops, (unsigned)count, (unsigned)MAX_RELAYS);
        return false;
    }
    if (cfg.buildAttempts == 0) return false;

    memcpy(dir_, directory, count * sizeof(Relay));
    count_   = count;
    cfg_     = cfg;
    pathOpt_ = opt;

    ONION_LOG("RNG source: %s", rngSourceName(rngSource()));

    queue_ = xQueueCreate(cfg_.queueDepth, sizeof(Request));
    if (!queue_) return false;

    if (xTaskCreatePinnedToCore(taskEntry, "onion", cfg_.stackBytes, this,
                                cfg_.priority, &task_, cfg_.core) != pdPASS) {
        vQueueDelete(queue_);
        queue_ = nullptr;
        return false;
    }
    return true;
}

uint32_t Client::send(uint32_t ip, uint16_t port, const void* data, size_t len, const uint8_t* destPub) {
    const size_t overhead = destPub ? E2E_REQUEST_OVERHEAD : 0;
    if (!queue_ || len + overhead > maxPayload(cfg_.hops) || len > sizeof(Request::data)) return 0;

    Request req;
    req.seq    = __atomic_add_fetch(&seq_, 1, __ATOMIC_RELAXED);
    req.ip     = ip;
    req.port   = port;
    req.len    = (uint16_t)len;
    req.sealed = destPub != nullptr;
    if (destPub) memcpy(req.destPub, destPub, PUB_SIZE);
    memcpy(req.data, data, len);
    return xQueueSend(queue_, &req, 0) == pdTRUE ? req.seq : 0;
}

// ---- Zadanie ---------------------------------------------------------------

void Client::taskEntry(void* self) {
    static_cast<Client*>(self)->run();
}

// Pętla zadania: bierze wiadomość z kolejki, wysyła ją i woła callback z wynikiem.
void Client::run() {
    Request req;
    for (;;) {
        xQueueReceive(queue_, &req, portMAX_DELAY);

        uint8_t    respBuf[maxResponse(MIN_HOPS)];
        SendResult result{req.seq, SendStatus::Failed, nullptr, 0};
        process(req, respBuf, &result);

        ONION_LOG("message #%u to %s:%u: %s (%u B response)", (unsigned)req.seq,
                  u32ToIp(req.ip).toString().c_str(), req.port, statusName(result.status),
                  (unsigned)result.responseLen);
        if (callback_) callback_(result);
    }
}

// Buduje obwód: wybiera ścieżkę (selectPath) i próbuje do buildAttempts razy.
bool Client::buildCircuit() {
    for (uint8_t attempt = 1; attempt <= cfg_.buildAttempts; attempt++) {
        Relay path[MAX_HOPS];
        if (!selectPath(dir_, count_, pathOpt_, path)) {
            ONION_LOG("path selection failed (no entropy?)");
            return false;
        }
        logPath(path, cfg_.hops);
        if (circuit_.build(path, cfg_.hops)) return true;
        ONION_LOG("circuit build failed (attempt %u/%u)", (unsigned)attempt, (unsigned)cfg_.buildAttempts);
    }
    return false;
}

// Obsługa jednej wiadomości: obwód (nowy albo ponownie użyty) -> opcjonalnie szyfrowanie e2e ->
// wysyłka -> odszyfrowanie odpowiedzi -> sprzątanie obwodu. Wynik trafia do *result.
void Client::process(const Request& req, uint8_t* respBuf, SendResult* result) {
    if (cfg_.networkUp && !cfg_.networkUp()) {
        ONION_LOG("network down, dropping message");
        return;
    }

    bool needNew = !cfg_.reuseCircuit || !circuit_.ready() ||
                   (cfg_.circuitMaxUses && uses_ >= cfg_.circuitMaxUses);
    if (needNew) {
        circuit_.destroy();                       // no-op, gdy obwodu nie ma
        if (!buildCircuit()) { result->status = SendStatus::NoCircuit; return; }
        uses_ = 0;
    }

    // Szyfrowanie end-to-end: exit dostaje tylko szyfrogram.
    uint8_t        sealed[CELL_PAYLOAD_SIZE];
    const uint8_t* payload = req.data;
    size_t         plen    = req.len;
    E2eKeys        keys;
    if (req.sealed) {
        if (!sealRequest(req.destPub, req.data, req.len, sealed, &keys)) return;
        payload = sealed;
        plen    = req.len + E2E_REQUEST_OVERHEAD;
    }

    Response resp{respBuf, maxResponse(MIN_HOPS)};
    SendStatus st = circuit_.send(req.ip, req.port, payload, plen,
                                  cfg_.waitForReply ? &resp : nullptr, cfg_.replyTimeoutMs);
    uses_++;

    result->status = st;
    if (resp.len > 0 && (st == SendStatus::Delivered || st == SendStatus::ExitFailed)) {
        if (!req.sealed) {
            result->response = resp.buf;
            result->responseLen = resp.len;
        } else {
            uint8_t plain[maxResponse(MIN_HOPS)];
            if (openResponse(keys, resp.buf, resp.len, plain)) {
                memcpy(respBuf, plain, resp.len - E2E_RESPONSE_OVERHEAD);   // wynik zastępuje szyfrogram
                result->response = respBuf;
                result->responseLen = resp.len - E2E_RESPONSE_OVERHEAD;
            } else {
                ONION_LOG("e2e: response authentication failed");
                result->status = SendStatus::Mismatch;
            }
        }
    }

    // Obwód zostaje tylko w trybie reuse i tylko gdy sam obwód działał (ExitFailed to problem celu).
    bool circuitOk = st == SendStatus::Delivered || st == SendStatus::Sent || st == SendStatus::ExitFailed;
    if (!circuitOk || !cfg_.reuseCircuit) circuit_.destroy();
}

}  // namespace onion
