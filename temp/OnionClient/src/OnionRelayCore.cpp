#include "OnionRelayCore.h"
#include "OnionCell.h"
#include "OnionCrypto.h"
#include "OnionTransport.h"

namespace onion {
namespace {

class Lock {
public:
    explicit Lock(SemaphoreHandle_t m) : m_(m) { xSemaphoreTake(m_, portMAX_DELAY); }
    ~Lock() { xSemaphoreGive(m_); }
private:
    SemaphoreHandle_t m_;
};

// Relay do wywołań exchangeCell (nazwa tylko do logów; klucz statyczny nie jest tu potrzebny).
Relay nextRelay(uint32_t ip, uint16_t port) {
    Relay r{};
    r.ip   = ip;
    r.port = port;
    strlcpy(r.name, "next", sizeof(r.name));
    return r;
}

}  // namespace

// ---- Start i tablica obwodów -----------------------------------------------

bool RelayCore::begin(const uint8_t* staticPriv, const uint8_t* staticPub, const RelayCoreConfig& cfg) {
    memcpy(priv_, staticPriv, 32);
    memcpy(pub_, staticPub, 32);
    cfg_ = cfg;
    if (cfg_.maxCircuits == 0 || cfg_.maxCircuits > MAX_RELAY_CIRCUITS) cfg_.maxCircuits = MAX_RELAY_CIRCUITS;
    memset(table_, 0, sizeof(table_));
    if (!mu_) mu_ = xSemaphoreCreateMutex();
    return mu_ != nullptr;
}

// Znajduje obwód i zwraca jego kopię; odświeża czas ostatniego ruchu. false = nie ma lub wygasł.
bool RelayCore::lookup(uint32_t id, CircuitEntry* copy) {
    Lock l(mu_);
    uint32_t now = millis();
    for (size_t i = 0; i < cfg_.maxCircuits; i++) {
        CircuitEntry& e = table_[i];
        if (!e.used || e.id != id) continue;
        if (now - e.lastMs > cfg_.circuitIdleMs) {   // wygasł
            memset(&e, 0, sizeof(e));
            stats_.evicted++;
            return false;
        }
        e.lastMs = now;
        *copy = e;
        return true;
    }
    return false;
}

// Zapisuje nowy obwód. Miejsce: ten sam id > wolne > wygasłe > najstarsze.
void RelayCore::store(uint32_t id, const uint8_t* key, uint8_t depth) {
    Lock l(mu_);
    uint32_t now = millis();

    int same = -1, freeIdx = -1, expired = -1, oldest = -1;
    for (size_t i = 0; i < cfg_.maxCircuits; i++) {
        CircuitEntry& e = table_[i];
        if (!e.used) { if (freeIdx < 0) freeIdx = (int)i; continue; }
        if (e.id == id) same = (int)i;
        uint32_t age = now - e.lastMs;
        if (age > cfg_.circuitIdleMs && expired < 0) expired = (int)i;
        if (oldest < 0 || age > now - table_[oldest].lastMs) oldest = (int)i;
    }
    int slot = same >= 0 ? same : freeIdx >= 0 ? freeIdx : expired >= 0 ? expired : oldest;
    if (slot != same && slot != freeIdx) stats_.evicted++;

    CircuitEntry& e = table_[slot];
    memset(&e, 0, sizeof(e));
    e.used   = true;
    e.id     = id;
    e.depth  = depth;
    e.lastMs = now;
    memcpy(e.key, key, KEY_SIZE);
}

// Zapamiętuje następny hop obwodu (po udanym EXTEND). Od tej chwili warstwy idą dalej po circuit id.
void RelayCore::setNext(uint32_t id, uint32_t ip, uint16_t port, uint32_t nextId) {
    Lock l(mu_);
    for (size_t i = 0; i < cfg_.maxCircuits; i++) {
        CircuitEntry& e = table_[i];
        if (e.used && e.id == id) {
            e.hasNext = true; e.nextIp = ip; e.nextPort = port; e.nextId = nextId;
            return;
        }
    }
}

bool RelayCore::remove(uint32_t id, CircuitEntry* removed) {
    Lock l(mu_);
    for (size_t i = 0; i < cfg_.maxCircuits; i++) {
        CircuitEntry& e = table_[i];
        if (e.used && e.id == id) {
            *removed = e;
            memset(&e, 0, sizeof(e));
            return true;
        }
    }
    return false;
}

void RelayCore::bump(uint32_t RelayStats::*field) {
    Lock l(mu_);
    ++(stats_.*field);
}

RelayStats RelayCore::stats() const {
    Lock l(mu_);
    return stats_;
}

size_t RelayCore::activeCircuits() const {
    Lock l(mu_);
    size_t n = 0;
    for (size_t i = 0; i < cfg_.maxCircuits; i++) if (table_[i].used) n++;
    return n;
}

// ---- Obsługa komórki -------------------------------------------------------

// Czyta jedną komórkę z kanału i kieruje ją do właściwego handlera.
void RelayCore::serve(Channel& ch) {
    Cell cell;
    if (!ch.read(&cell, sizeof(cell), cfg_.readTimeoutMs)) return;

    switch (cell.command) {
        case CMD_CREATE:  onCreate(ch, cell); break;
        case CMD_RELAY:   onRelay(ch, cell);  break;
        case CMD_DESTROY: onDestroy(cell);    break;
        default:
            ONION_LOG("relay: unknown cmd 0x%02x", cell.command);
            bump(&RelayStats::rejected);
    }
}

// CREATE { wersja, głębokość, E }: sprawdza wersję, robi handshake i odpowiada CREATED { R, MAC }.
// Obca wersja dostaje DESTROY z numerem wersji tego relaya, więc klient od razu wie, co jest nie tak.
void RelayCore::onCreate(Channel& ch, const Cell& in) {
    const uint8_t version = in.payload[0], depth = in.payload[1];

    if (version != PROTO_VERSION) {
        ONION_LOG("relay: CREATE with protocol v%u, this relay speaks v%u", (unsigned)version, (unsigned)PROTO_VERSION);
        uint8_t mine = PROTO_VERSION;
        Cell out;
        makeCell(out, in.circuitId, CMD_DESTROY, &mine, 1);
        ch.write(&out, sizeof(out));
        bump(&RelayStats::rejected);
        return;
    }
    if (depth >= MAX_HOPS) { bump(&RelayStats::rejected); return; }

    uint8_t body[PUB_SIZE + HMAC_SIZE], key[KEY_SIZE];   // body = R | MAC
    if (!Handshake::respond(version, in.payload + 2, priv_, pub_, body, body + PUB_SIZE, key)) {
        ONION_LOG("relay: CREATE rejected (bad client key or no entropy)");
        bump(&RelayStats::rejected);
        return;
    }
    store(in.circuitId, key, depth);

    Cell out;
    makeCell(out, in.circuitId, CMD_CREATED, body, sizeof(body));
    ch.write(&out, sizeof(out));
    bump(&RelayStats::created);
    ONION_LOG("relay: CREATE %08x depth=%u -> CREATED", (unsigned)in.circuitId, (unsigned)depth);
}

// RELAY: zdejmuje swoją warstwę (AES-GCM). Zmieniona warstwa jest porzucana. Potem:
//   ma następny hop -> przekazuje dalej według stanu obwodu,
//   nie ma          -> wykonuje polecenie z tekstu końcowego (EXTEND albo DATA).
void RelayCore::onRelay(Channel& ch, const Cell& in) {
    CircuitEntry st;
    if (!lookup(in.circuitId, &st)) {
        ONION_LOG("relay: RELAY on unknown circuit %08x", (unsigned)in.circuitId);
        bump(&RelayStats::rejected);
        return;
    }

    uint8_t inner[CELL_PAYLOAD_SIZE];
    if (!decryptLayer(st.key, DIR_FORWARD, in.payload, layerSize(st.depth), inner)) {
        ONION_LOG("relay: layer authentication failed on circuit %08x, dropped", (unsigned)in.circuitId);
        bump(&RelayStats::authFailed);
        return;
    }

    if (st.hasNext)                    onForward(ch, in.circuitId, st, inner);
    else if (inner[0] == T_EXTEND)     onExtend(ch, in.circuitId, st, inner);
    else if (inner[0] == T_DATA)       onExit(ch, in, st, inner);
    else {
        ONION_LOG("relay: unknown command 0x%02x", inner[0]);
        bump(&RelayStats::rejected);
    }
}

// Środek obwodu: zdjęta warstwa to cała warstwa następnego hopa. Przekazujemy ją pod id obwodu
// na następnym łączu, a odpowiedź owijamy własną warstwą i odsyłamy.
void RelayCore::onForward(Channel& ch, uint32_t cid, const CircuitEntry& st, const uint8_t* nextLayer) {
    const size_t nextSize = layerSize(st.depth + 1);

    Cell fwd, rsp;
    makeCell(fwd, st.nextId, CMD_RELAY, nextLayer, nextSize);
    if (!exchangeCell(nextRelay(st.nextIp, st.nextPort), fwd, &rsp, cfg_.forwardTimeoutMs)) return;
    if (rsp.command != CMD_RELAY || rsp.circuitId != st.nextId) return;

    uint8_t out[CELL_PAYLOAD_SIZE];
    if (!encryptLayer(st.key, DIR_BACKWARD, rsp.payload, nextSize, out)) return;

    Cell reply;
    makeCell(reply, cid, CMD_RELAY, out, layerSize(st.depth));
    if (ch.write(&reply, sizeof(reply))) bump(&RelayStats::forwarded);
}

// EXTEND { ip, port, wersja, E }: wysyła CREATE do nowego relaya w imieniu klienta i odsyła
// EXTENDED { R, MAC }. Od tej pory ten obwód ma następny hop.
void RelayCore::onExtend(Channel& ch, uint32_t cid, const CircuitEntry& st, const uint8_t* text) {
    if (st.depth + 1 >= MAX_HOPS) { bump(&RelayStats::rejected); return; }

    const uint32_t ip      = getLE32(text + 1);
    const uint16_t port    = getLE16(text + 5);
    const uint8_t  version = text[7];

    uint32_t newId;
    if (!randomBytes(&newId, sizeof(newId))) return;

    uint8_t body[2 + PUB_SIZE] = {version, (uint8_t)(st.depth + 1)};   // wersja | głębokość nowego hopa | E
    memcpy(body + 2, text + 8, PUB_SIZE);

    Cell create, rsp;
    makeCell(create, newId, CMD_CREATE, body, sizeof(body));
    if (!exchangeCell(nextRelay(ip, port), create, &rsp, cfg_.forwardTimeoutMs)) return;
    if (rsp.command == CMD_DESTROY) {
        ONION_LOG("relay: EXTEND: next relay speaks protocol v%u", (unsigned)rsp.payload[0]);
        return;
    }
    if (rsp.command != CMD_CREATED || rsp.circuitId != newId) return;
    setNext(cid, ip, port, newId);

    uint8_t reply[CELL_PAYLOAD_SIZE] = {0};                            // EXTENDED | R | MAC | zera
    reply[0] = T_EXTENDED;
    memcpy(reply + 1, rsp.payload, PUB_SIZE + HMAC_SIZE);
    if (replyTerminal(ch, cid, st, reply)) bump(&RelayStats::extended);
}

// DATA { ip, port, długość, dane } w ostatnim hopie (exit): dostarcza dane do celu zwykłym TCP,
// zbiera odpowiedź i odsyła DATA_REPLY { status, nonce_żądania, odpowiedź }. Nonce naszej warstwy
// (pierwsze 12 B payloadu) wraca do klienta, żeby wiązał odpowiedź z tą wiadomością.
void RelayCore::onExit(Channel& ch, const Cell& in, const CircuitEntry& st, const uint8_t* text) {
    const uint32_t ip   = getLE32(text + 1);
    const uint16_t port = getLE16(text + 5);
    const size_t   len  = getLE16(text + 7);
    const size_t   size = layerSize(st.depth) - LAYER_OVERHEAD;        // rozmiar tekstu końcowego
    if (DATA_HEADER_SIZE + len > size) { bump(&RelayStats::rejected); return; }

    uint8_t resp[CELL_PAYLOAD_SIZE];
    size_t  respLen = 0;
    uint8_t status  = STATUS_FAILED;
    if (!cfg_.exitPolicy || !cfg_.exitPolicy(ip, port)) {
        ONION_LOG("relay: exit to %s:%u denied by policy", u32ToIp(ip).toString().c_str(), (unsigned)port);
        bump(&RelayStats::rejected);
    } else if (tcpExchange(ip, port, text + DATA_HEADER_SIZE, len, resp, size - REPLY_HEADER_SIZE,
                           &respLen, cfg_.exitTimeoutMs)) {
        status = STATUS_OK;
        bump(&RelayStats::delivered);
        ONION_LOG("relay: EXIT -> %s:%u (%u B, reply %u B)", u32ToIp(ip).toString().c_str(),
                  (unsigned)port, (unsigned)len, (unsigned)respLen);
    } else {
        bump(&RelayStats::deliveryFailed);
    }

    uint8_t reply[CELL_PAYLOAD_SIZE];
    buildReply(reply, size, status, in.payload, resp, respLen);
    replyTerminal(ch, in.circuitId, st, reply);
}

// DESTROY: usuwa obwód i przekazuje DESTROY dalej pod id obwodu na następnym łączu.
void RelayCore::onDestroy(const Cell& in) {
    CircuitEntry st;
    if (!remove(in.circuitId, &st)) {
        ONION_LOG("relay: DESTROY unknown circuit %08x", (unsigned)in.circuitId);
        return;
    }
    bump(&RelayStats::destroyed);
    ONION_LOG("relay: DESTROY %08x", (unsigned)in.circuitId);

    if (st.hasNext) {
        Cell d;
        makeCell(d, st.nextId, CMD_DESTROY, nullptr, 0);
        exchangeCell(nextRelay(st.nextIp, st.nextPort), d, nullptr);
    }
}

bool RelayCore::replyTerminal(Channel& ch, uint32_t cid, const CircuitEntry& st, const uint8_t* text) {
    uint8_t layer[CELL_PAYLOAD_SIZE];
    if (!encryptLayer(st.key, DIR_BACKWARD, text, layerSize(st.depth) - LAYER_OVERHEAD, layer)) return false;

    Cell out;
    makeCell(out, cid, CMD_RELAY, layer, layerSize(st.depth));
    return ch.write(&out, sizeof(out));
}

}  // namespace onion
