#include "OnionTlsServer.h"
#include "OnionRandom.h"

#include <mbedtls/ssl.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/pk.h>
#include <lwip/sockets.h>
#include <unistd.h>
#include <errno.h>

namespace onion {
namespace {

// Kody błędów z mbedtls/net_sockets.h wpisane wprost, żeby nie zależeć od tego nagłówka.
constexpr int ERR_ENTROPY  = -0x003C;   // MBEDTLS_ERR_ENTROPY_SOURCE_FAILED
constexpr int ERR_NET_SEND = -0x004E;   // MBEDTLS_ERR_NET_SEND_FAILED
constexpr int ERR_NET_RECV = -0x004C;   // MBEDTLS_ERR_NET_RECV_FAILED

int rngCb(void*, unsigned char* buf, size_t len) {
    return randomBytes(buf, len) ? 0 : ERR_ENTROPY;
}

bool wouldBlock() { return errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR; }

// Gniazdo ma SO_RCVTIMEO/SO_SNDTIMEO = 1 s, więc EAGAIN oznacza "nic jeszcze"; terminy
// pilnują pętle w handshake/read/write.
int sendCb(void* ctx, const unsigned char* buf, size_t len) {
    int r = (int)send(*(int*)ctx, buf, len, 0);
    if (r >= 0) return r;
    return wouldBlock() ? MBEDTLS_ERR_SSL_WANT_WRITE : ERR_NET_SEND;
}

int recvCb(void* ctx, unsigned char* buf, size_t len) {
    int r = (int)recv(*(int*)ctx, buf, len, 0);
    if (r >= 0) return r;                    // 0 = EOF
    return wouldBlock() ? MBEDTLS_ERR_SSL_WANT_READ : ERR_NET_RECV;
}

bool expired(uint32_t deadline) { return (int32_t)(millis() - deadline) > 0; }

bool wantMore(int r) { return r == MBEDTLS_ERR_SSL_WANT_READ || r == MBEDTLS_ERR_SSL_WANT_WRITE; }

class TlsChannel : public Channel {
public:
    explicit TlsChannel(mbedtls_ssl_context& ssl) : ssl_(ssl) {}

    bool read(void* buf, size_t len, uint32_t timeoutMs) override {
        uint8_t* p = (uint8_t*)buf;
        size_t   got = 0;
        uint32_t deadline = millis() + timeoutMs;
        while (got < len) {
            int r = mbedtls_ssl_read(&ssl_, p + got, len - got);
            if (r > 0)              got += r;
            else if (wantMore(r)) { if (expired(deadline)) return false; }
            else                    return false;
        }
        return true;
    }

    bool write(const void* buf, size_t len) override {
        const uint8_t* p = (const uint8_t*)buf;
        size_t   sent = 0;
        uint32_t deadline = millis() + 10000;
        while (sent < len) {
            int r = mbedtls_ssl_write(&ssl_, p + sent, len - sent);
            if (r > 0)              sent += r;
            else if (wantMore(r)) { if (expired(deadline)) return false; }
            else                    return false;
        }
        return true;
    }

private:
    mbedtls_ssl_context& ssl_;
};

}  // namespace

struct TlsServer::Impl {
    mbedtls_ssl_config conf;
    mbedtls_x509_crt   cert;
    mbedtls_pk_context key;
};

TlsServer::~TlsServer() {
    if (!impl_) return;
    mbedtls_ssl_config_free(&impl_->conf);
    mbedtls_x509_crt_free(&impl_->cert);
    mbedtls_pk_free(&impl_->key);
    delete impl_;
}

bool TlsServer::begin(const char* certPem, const char* keyPem) {
    if (impl_) return false;
    impl_ = new Impl;
    mbedtls_ssl_config_init(&impl_->conf);
    mbedtls_x509_crt_init(&impl_->cert);
    mbedtls_pk_init(&impl_->key);

    int ret = mbedtls_x509_crt_parse(&impl_->cert, (const unsigned char*)certPem, strlen(certPem) + 1);
    if (!ret) ret = mbedtls_pk_parse_key(&impl_->key, (const unsigned char*)keyPem, strlen(keyPem) + 1,
                                         nullptr, 0, rngCb, nullptr);
    if (!ret) ret = mbedtls_ssl_config_defaults(&impl_->conf, MBEDTLS_SSL_IS_SERVER,
                                                MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
    if (!ret) {
        mbedtls_ssl_conf_rng(&impl_->conf, rngCb, nullptr);
        ret = mbedtls_ssl_conf_own_cert(&impl_->conf, &impl_->cert, &impl_->key);
    }
    if (ret) ONION_LOG("tls server: setup failed: -0x%04X (bad PEM or mbedTLS built without server support)",
                       (unsigned)-ret);
    return ret == 0;
}

void TlsServer::handle(int fd, RelayCore& core) {
    struct timeval tv = {1, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    mbedtls_ssl_context ssl;
    mbedtls_ssl_init(&ssl);

    bool ok = mbedtls_ssl_setup(&ssl, &impl_->conf) == 0;
    if (ok) {
        mbedtls_ssl_set_bio(&ssl, &fd, sendCb, recvCb, nullptr);

        uint32_t deadline = millis() + 15000;
        int r;
        while ((r = mbedtls_ssl_handshake(&ssl)) != 0) {
            if (!wantMore(r) || expired(deadline)) {
                ONION_LOG("tls server: handshake failed: -0x%04X", (unsigned)-r);
                ok = false;
                break;
            }
        }
    }

    if (ok) {
        TlsChannel ch(ssl);
        core.serve(ch);
        mbedtls_ssl_close_notify(&ssl);
    }
    mbedtls_ssl_free(&ssl);
    close(fd);
}

}  // namespace onion
