
#include <EspNowAESBroadcast.h>

#define ESP_NOW_CHANNEL 1
//AES 128bit
unsigned char secredKey[] = {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE, 0xFF};

void espNowAESBroadcastRecv(const uint8_t *data, int len, uint16_t replyPrt){
}

void setup() {
  Serial.begin(115200);
  //Set device in AP mode to begin with
  espNowAESBroadcast_RecvCB(espNowAESBroadcastRecv);
  espNowAESBroadcast_secredkey(secredKey);
  espNowAESBroadcast_begin(ESP_NOW_CHANNEL);
  espNowAESBroadcast_setToMasterRole(true,3); //Set ttl to 3.
}

void loop() {
  static unsigned long m = millis();
  if(m+5000<millis()) {
    char message2[] = "MARCO";
    espNowAESBroadcast_sendAndHandleReply((uint8_t*)message2, sizeof(message2),3,[](const uint8_t *data, int len){
        if(len>0) {
          Serial.print(">");
          Serial.println((const char*)data);
        }
    });
    m = millis();
  }
  espNowAESBroadcast_loop();
  delay(10);
}
