
#include <EspNowFloodingMesh.h>
#include <time.h>
#define ESP_NOW_CHANNEL 1
//AES 128bit
unsigned char secredKey[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};

void espNowFloodingMeshRecv(const uint8_t *data, int len, uint32_t replyPrt){
  if (len > 0) {
    Serial.println((const char*)data);
  }
}

void setup() {
  Serial.begin(115200);
  //Set device in AP mode to begin with
  espNowFloodingMesh_RecvCB(espNowFloodingMeshRecv);
  espNowFloodingMesh_begin(ESP_NOW_CHANNEL);
  espNowFloodingMesh_secredkey(secredKey);
  espNowFloodingMesh_setToBatteryNode();
}

void loop() {
  static unsigned long m = millis();

  //Ask instant sync from master.
  espNowFloodingMesh_requestInstantTimeSyncFromMaster();
  while (espNowFloodingMesh_isSyncedWithMaster() == false);
  char message[] = "SLAVE(12) HELLO MESSAGE";
  espNowFloodingMesh_send((uint8_t*)message, sizeof(message), 3); //set ttl to 3
  espNowFloodingMesh_loop();
  ESP.deepSleep(60000, WAKE_RF_DEFAULT); //Wakeup every minute
}
