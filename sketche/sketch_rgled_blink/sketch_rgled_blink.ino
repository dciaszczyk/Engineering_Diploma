#define RGBLED 38

void cycle3();
void cyclerainbow();

void setup() {
  pinMode(RGBLED, OUTPUT);
  Serial.begin(115200);
  Serial.onEvent(ARDUINO_HW_CDC_RX_EVENT, handleSerialMessage);
}

int mode = 0;

void loop() {
  Serial.println("loop");
  if (mode == 0)
    cycle3();
  else cyclerainbow();
  delay(100);
}

void handleSerialMessage(void* arg, esp_event_base_t base, int32_t id, void* data) {
  if (id == ARDUINO_HW_CDC_RX_EVENT) {
    while (Serial.available()) {
      char c = Serial.read();
      if (c == '1') mode = 1;
      else if (c == '0') mode = 0;
      Serial.print(c);
    }
    Serial.print('\n');
  }
}

void cycle3(){
  rgbLedWrite(RGBLED, 100, 0, 0);
  delay(1000);
  rgbLedWrite(RGBLED, 0, 100, 0);
  delay(1000);
  rgbLedWrite(RGBLED, 0, 0, 100);
  delay(1000);
}

void cyclerainbow(){
  int red, green, blue;

  red = 100;
  green= 0;
  blue = 0;
  
  for(int i=0;i<100;i++){
    rgbLedWrite(RGBLED, red, green, blue);
    green++;
    delay(10);
  }

  for(int i=0;i<100;i++){
    rgbLedWrite(RGBLED, red, green, blue);
    red--;
    delay(10);
  }

  for(int i=0;i<100;i++){
    rgbLedWrite(RGBLED, red, green, blue);
    blue++;
    delay(10);
  }

  for(int i=0;i<100;i++){
    rgbLedWrite(RGBLED, red, green, blue);
    green--;
    delay(10);
  }

  for(int i=0;i<100;i++){
    rgbLedWrite(RGBLED, red, green, blue);
    red++;
    delay(10);
  }

  for(int i=0;i<100;i++){
    rgbLedWrite(RGBLED, red, green, blue);
    blue--;
    delay(10);
  }
}