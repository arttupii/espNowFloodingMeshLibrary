#include <EspNowAESBroadcast.h>

#define ESP_NOW_CHANNEL 1
//AES 128bit
unsigned char secredKey[] = {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE, 0xFF};

void espNowAESBroadcastRecv(const uint8_t *data, int len, uint32_t replyPrt){
  if(len>0) {
    if(replyPrt) { //Reply asked. Send reply
        char m[]="POLO";
        Serial.println((char*)data); //Print MARCO
        espNowAESBroadcast_sendReply((uint8_t*)m, sizeof(m), 0/*ttl*/, replyPrt);
    }
  }
}

void setup() {
  Serial.begin(115200);
  //Set device in AP mode to begin with
  espNowAESBroadcast_RecvCB(espNowAESBroadcastRecv);
  espNowAESBroadcast_secredkey(secredKey);
  espNowAESBroadcast_begin(ESP_NOW_CHANNEL);
  
  espNowAESBroadcast_requestInstantTimeSyncFromMaster();
  while (espNowAESBroadcast_isSyncedWithMaster() == false);
}

void loop() {
  espNowAESBroadcast_loop();
  delay(10);

  static unsigned long m = millis();
  if(m+5000<millis()) {
    char message[] = "SLAVE(ESP01) HELLO MESSAGE";
    espNowAESBroadcast_send((uint8_t*)message, sizeof(message));
    m = millis();
  }
  espNowAESBroadcast_loop();
  delay(10);
}
