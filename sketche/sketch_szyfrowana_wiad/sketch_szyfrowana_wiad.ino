#include <WiFi.h>
#include <HTTPClient.h>
#include "mbedtls/aes.h"
#include "esp_system.h"   // esp_random()

#define MAX_PAYLOAD_SIZE 255 //tor używa 514?

struct message 
{
  uint32_t targetIP;
  uint16_t targetPort;
  uint8_t payloadLength;
  uint8_t payload[MAX_PAYLOAD_SIZE];
};

const char* ssid = "iprivate-4";
const char* password = "Tciaszczyk1980";

// adres na razie udający relay
const char* relayURL = "http://172.16.102.243:8001/relay";

const uint32_t RELAY_HOST_IP = 0xAC1066F3; // 172.16.102.243

const uint16_t RELAY1_PORT = 8001;
const uint16_t RELAY2_PORT = 8002;
const uint16_t RELAY3_PORT = 8003;

// adres wewnętrznej wiadomości
const uint32_t TARGET_IP = 0xAC1066F3; 
const uint16_t TARGET_PORT = 9000;

//statyczne klucze do prototypu

const uint8_t KEY1[32] = {
    0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
    0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
    0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
    0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f
};
const uint8_t KEY2[32] = {
    0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,
    0x28,0x29,0x2a,0x2b,0x2c,0x2d,0x2e,0x2f,
    0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,
    0x38,0x39,0x3a,0x3b,0x3c,0x3d,0x3e,0x3f
};
const uint8_t KEY3[32] = {
    0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,
    0x48,0x49,0x4a,0x4b,0x4c,0x4d,0x4e,0x4f,
    0x50,0x51,0x52,0x53,0x54,0x55,0x56,0x57,
    0x58,0x59,0x5a,0x5b,0x5c,0x5d,0x5e,0x5f
};

struct RelayInfo {
    uint32_t ip;
    uint16_t port;
    const uint8_t* key; 
};

size_t aesEncrypt(const uint8_t* data, size_t len, const uint8_t* key, uint8_t* out)
{
    uint8_t iv[16];
    for (int i = 0; i < 16; i++) iv[i] = (uint8_t)(esp_random() & 0xFF);
    memcpy(out, iv, 16);

    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);
    mbedtls_aes_setkey_enc(&ctx, key, 256);

    size_t nc_off = 0;
    uint8_t nonce[16], stream[16];
    memcpy(nonce, iv, 16);
    memset(stream, 0, 16);

    mbedtls_aes_crypt_ctr(&ctx, len, &nc_off, nonce, stream, data, out + 16);

    mbedtls_aes_free(&ctx);
    return 16 + len;
}

size_t aesDecrypt(const uint8_t* data, size_t len, const uint8_t* key, uint8_t* out)
{
    if (len < 16) return 0;

    uint8_t iv[16];
    memcpy(iv, data, 16);

    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);
    mbedtls_aes_setkey_enc(&ctx, key, 256); 

    size_t nc_off = 0;
    uint8_t nonce[16], stream[16];
    memcpy(nonce, iv, 16);
    memset(stream, 0, 16);

    size_t plainLen = len - 16;
    mbedtls_aes_crypt_ctr(&ctx, plainLen, &nc_off, nonce, stream, data + 16, out);

    mbedtls_aes_free(&ctx);
    return plainLen;
}

// zamiana struct na bajty ( i z powrotem)
size_t serializeMessage(const message* msg, uint8_t* out) 
{
  size_t size = 0;
  memcpy(out + size, &msg->targetIP, 4); size += 4;
  memcpy(out + size, &msg->targetPort, 2); size += 2;
  memcpy(out + size, &msg->payloadLength, 1); size += 1;
  memcpy(out + size, msg->payload, msg->payloadLength); size += msg->payloadLength;
  return size;
}

void deserializeMessage(const uint8_t* in, size_t len, message* msg) 
{
  size_t size = 0;
  memcpy(&msg->targetIP,     in + size, 4); size += 4;
  memcpy(&msg->targetPort,   in + size, 2); size += 2;
  memcpy(&msg->payloadLength,in + size, 1); size += 1;
  memcpy(msg->payload,       in + size, msg->payloadLength);
}

// budowa oryginalnej wiadomości, i opakowywanie w warstwy
void buildOnion(uint32_t finalIP, uint16_t finalPort, const uint8_t* data, uint8_t dataLen, const RelayInfo* relays, int numRelays, message* outerOut)
{
    message current;
    current.targetIP   = finalIP;
    current.targetPort = finalPort;
    current.payloadLength = (uint8_t)aesEncrypt(
        data, dataLen, relays[numRelays - 1].key, current.payload);

    for (int i = numRelays - 2; i >= 0; i--) {
        message wrapper;
        wrapper.targetIP   = relays[i + 1].ip;
        wrapper.targetPort = relays[i + 1].port;

        uint8_t serialized[sizeof(message)];
        size_t  serializedLen = serializeMessage(&current, serialized);

        wrapper.payloadLength = (uint8_t)aesEncrypt(
            serialized, serializedLen, relays[i].key, wrapper.payload);

        current = wrapper;
    }

    *outerOut = current;
}

// sieć
void connectWiFi() 
{
  Serial.printf("Connecting to %s\n", ssid);
  WiFi.begin(ssid, password);
  while (WiFi.status() != WL_CONNECTED) {
      delay(500);
      Serial.print(".");
  }
  Serial.printf("\nConnected, IP: %s\n", WiFi.localIP().toString().c_str());
}

void setup() 
{
    Serial.begin(115200);
    connectWiFi();
}

void loop() 
{
    const char* text = "hello world";

    RelayInfo path[3] = {
        { RELAY_HOST_IP, RELAY1_PORT, KEY1 },
        { RELAY_HOST_IP, RELAY2_PORT, KEY2 },
        { RELAY_HOST_IP, RELAY3_PORT, KEY3 },
    };

    message cell;
    buildOnion(TARGET_IP, TARGET_PORT,
               (const uint8_t*)text, (uint8_t)strlen(text),
               path, 3, &cell);


    uint8_t wire[sizeof(message)];
    size_t  wireLen = serializeMessage(&cell, wire);

    HTTPClient http;
    http.begin(relayURL);
    http.addHeader("Content-Type", "application/octet-stream");
    int code = http.POST(wire, wireLen);
    Serial.printf("POST -> %d, sent %u bytes\n", code, (unsigned)wireLen);
    http.end();

    delay(2000);
}
