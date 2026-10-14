#include <WiFi.h>
#include <HTTPClient.h>

#define MAX_PAYLOAD_SIZE 255

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

const uint16_t RELAY2_PORT = 8002;
const uint16_t RELAY3_PORT = 8003;

// adres wewnętrznej wiadomości
const uint32_t TARGET_IP = 0xAC1066F3; 
const uint16_t TARGET_PORT = 9000;

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
void buildFirstLayer(uint32_t targetIP, uint16_t targetPort, uint8_t payloadLength, const uint8_t* data, message* messageCell) 
{
  messageCell->targetIP = targetIP;
  messageCell->targetPort = targetPort;
  messageCell->payloadLength = payloadLength;
  memcpy(messageCell->payload, data, payloadLength);
}

void buildNextLayer(uint32_t targetIP, uint16_t targetPort, const message* data, message* messageCell) 
{
  uint8_t byteMessage[sizeof(message)];
  size_t  byteMessageLength = serializeMessage(data, byteMessage);

  // uint8_t cipher[sizeof(message)];
  // size_t  cipherLength = Encrypt(byteMessage, byteMessageLength, cipher); //szyfrowanie

  messageCell->targetIP = targetIP;
  messageCell->targetPort = targetPort;
  
  messageCell->payloadLength = (uint8_t)byteMessageLength;
  //messageCell->payloadLength = (uint8_t)cipherLength;

  memcpy(messageCell->payload, byteMessage, byteMessageLength);
  //memcpy(messageCell->payload, cipher, cipherLength);

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
    message cell;
    buildFirstLayer(TARGET_IP, TARGET_PORT, (uint8_t)strlen(text), (const uint8_t*)text, &cell);
    message wrapper;
    buildNextLayer(RELAY_HOST_IP, RELAY3_PORT, &cell, &wrapper);
    cell = wrapper;
    buildNextLayer(RELAY_HOST_IP, RELAY2_PORT, &cell, &wrapper);
    cell = wrapper;


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
