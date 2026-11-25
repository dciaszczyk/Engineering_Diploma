#include "OnionRelay.h"
#include <lwip/sockets.h>
#include <unistd.h>

namespace onion {

bool RelayNode::begin(const RelayConfig& cfg) {
    if (conns_) return false;   // już wystartował
    if (!cfg.certPem || !cfg.keyPem) {
        ONION_LOG("relay: certPem and keyPem are required");
        return false;
    }
    if (cfg.workers == 0 || cfg.backlog == 0) return false;
    cfg_ = cfg;

    ONION_LOG("RNG source: %s", rngSourceName(rngSource()));
    if (!loadOrCreateIdentity(id_, cfg_.nvsNamespace)) return false;
    pubToHex(id_.pub, pubHex_);

    RelayCoreConfig cc;
    cc.exitPolicy       = cfg_.exitPolicy;
    cc.maxCircuits      = cfg_.maxCircuits;
    cc.circuitIdleMs    = cfg_.circuitIdleMs;
    cc.forwardTimeoutMs = cfg_.forwardTimeoutMs;
    cc.exitTimeoutMs    = cfg_.exitTimeoutMs;
    if (!core_.begin(id_.priv, id_.pub, cc)) return false;
    if (!tls_.begin(cfg_.certPem, cfg_.keyPem)) return false;

    listenFd_ = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listenFd_ < 0) return false;
    int one = 1;
    setsockopt(listenFd_, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in addr = {};
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port        = htons(cfg_.port);
    if (bind(listenFd_, (struct sockaddr*)&addr, sizeof(addr)) != 0 ||
        listen(listenFd_, cfg_.backlog) != 0) {
        ONION_LOG("relay: bind/listen on port %u failed", (unsigned)cfg_.port);
        close(listenFd_);
        listenFd_ = -1;
        return false;
    }

    conns_ = xQueueCreate(cfg_.backlog, sizeof(int));
    if (!conns_) return false;

    for (uint8_t i = 0; i < cfg_.workers; i++) {
        if (xTaskCreatePinnedToCore(workerEntry, "onion-rw", cfg_.stackBytes, this,
                                    cfg_.priority, nullptr, cfg_.core) != pdPASS) return false;
    }
    if (xTaskCreatePinnedToCore(acceptEntry, "onion-acc", 4096, this,
                                cfg_.priority, nullptr, cfg_.core) != pdPASS) return false;

    if (cfg_.directoryUrl &&
        xTaskCreatePinnedToCore(registerEntry, "onion-reg", 8192, this, 1, nullptr, cfg_.core) != pdPASS) return false;

    ONION_LOG("relay listening on :%u, static pub %s", (unsigned)cfg_.port, pubHex_);
    return true;
}

void RelayNode::acceptEntry(void* self) { static_cast<RelayNode*>(self)->acceptLoop(); }
void RelayNode::workerEntry(void* self) { static_cast<RelayNode*>(self)->workerLoop(); }
void RelayNode::registerEntry(void* self) { static_cast<RelayNode*>(self)->registerLoop(); }

// Wrzuca do katalogu nazwę, port i klucz publiczny (IP ustala katalog). Przy błędzie ponawia po 5 s,
// po sukcesie odświeża wpis co registerIntervalMs (katalog usuwa wpisy, które przestały się odświeżać).
void RelayNode::registerLoop() {
    bool registered = false;
    for (;;) {
        bool ok = registerNode(cfg_.directoryUrl, "relay", cfg_.name, cfg_.port, pubHex_);
        if (ok && !registered) ONION_LOG("registered in directory %s", cfg_.directoryUrl);
        if (!ok && registered) ONION_LOG("directory registration failed (%s)", cfg_.directoryUrl);
        registered = ok;
        vTaskDelay(pdMS_TO_TICKS(ok ? cfg_.registerIntervalMs : 5000));
    }
}

void RelayNode::acceptLoop() {
    for (;;) {
        int fd = accept(listenFd_, nullptr, nullptr);
        if (fd < 0) { vTaskDelay(pdMS_TO_TICKS(100)); continue; }

        int one = 1;
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
        if (xQueueSend(conns_, &fd, 0) != pdTRUE) {
            ONION_LOG("relay: all workers busy, dropping connection");
            close(fd);
        }
    }
}

void RelayNode::workerLoop() {
    for (;;) {
        int fd;
        xQueueReceive(conns_, &fd, portMAX_DELAY);
        tls_.handle(fd, core_);
    }
}

}  // namespace onion
