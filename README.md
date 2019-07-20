# ESPNOW flooding mesh library

See example project: https://github.com/arttupii/EspNowFloodingMesh

ESPNOW flooding mesh library.

Features:
- Maximum number of slave nodes: unlimited
- Number of master nodes: 1
- Master node sends time sync message every 10s to all nodes. (clocks are syncronised)
- Every message has a time stamp. If the time stamp is too old (or from the future), the message will be rejected.
- All messages are crypted (AES128)
- Flooding mesh support
- TTL support (time to life) 
- ESP32, ESP2866, ESP01
- Battery node support
- Request&Reply support


## Flooding mesh network
In this network example ttl must be >= 4
```
               SlaveNode
                   |
                   |         Message from master to BatteryNode
                   |   ---------------------------+
                   |                     ttl=4    |
SlaveNode-------MasterNode-------------SlaveNode  |
                   |                     |        |
                   |                     |        |
                   |                     |        |
                   |                     |        |
               SlaveNode                 |        |
                   |                     |        |
                   |                     |        |
                   |                     |        +------------------------------------------------>
                   |                     | ttl=3         ttl=2              ttl=1
SlaveNode-------SlaveNode-------------SlaveNode-------SlaveNode-------------SlaveNode---------BatteryNode
   |               |                     |
   |               |                     |
   |               |                     |
   |               |                     |
   +-----------SlaveNode-----------------+
```  
## Create master node:
```c++
#include <EspNowAESBroadcast.h>

#define ESP_NOW_CHANNEL 1
//AES 128bit
unsigned char secredKey[] = {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE, 0xFF};

void espNowAESBroadcastRecv(const uint8_t *data, int len){
  if(len>0) {
    Serial.println((const char*)data);
  }
}

void setup() {
  Serial.begin(115200);

  espNowAESBroadcast_RecvCB(espNowAESBroadcastRecv);
  espNowAESBroadcast_secredkey(secredKey);
  espNowAESBroadcast_begin(ESP_NOW_CHANNEL);
  espNowAESBroadcast_setToMasterRole(true,3); //Set ttl to 3. TIME_SYNC message use this ttl
  espNowAESBroadcast_ErrorDebugCB([](int level, const char *str) {
    Serial.println(str);
  });
}

void loop() {
  static unsigned long m = millis();
  if(m+5000<millis()) {
    char message[] = "MASTER HELLO MESSAGE";
    espNowAESBroadcast_send((uint8_t*)message, sizeof(message), 3); //set ttl to 3
    m = millis();
  }
  espNowAESBroadcast_loop();
  delay(10);
}
```
## Create slave node:
```c++
#include <EspNowAESBroadcast.h>

#define ESP_NOW_CHANNEL 1
//AES 128bit
unsigned char secredKey[] = {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF};

void espNowAESBroadcastRecv(const uint8_t *data, int len){
  if(len>0) {
    Serial.println((const char*)data);
  }
}

void setup() {
  Serial.begin(115200);

  espNowAESBroadcast_RecvCB(espNowAESBroadcastRecv);
  espNowAESBroadcast_begin(ESP_NOW_CHANNEL);
  espNowAESBroadcast_secredkey(secredKey);

  //Ask instant sync from master.
  espNowAESBroadcast_requestInstantTimeSyncFromMaster();
  espNowAESBroadcast_ErrorDebugCB([](int level, const char *str) {
    Serial.println(str);
  });
  while(espNowAESBroadcast_isSyncedWithMaster()==false);
}

void loop() {
  static unsigned long m = millis();
  if(m+5000<millis()) {
    char message[] = "SLAVE HELLO MESSAGE";
    espNowAESBroadcast_send((uint8_t*)message, sizeof(message), 3); //set ttl to 3
    m = millis();
  }
  espNowAESBroadcast_loop();
  delay(10);
}
```

## Create slave node (Battery):
```c++
#include <EspNowAESBroadcast.h>
#include <time.h>
#define ESP_NOW_CHANNEL 1
//AES 128bit
unsigned char secredKey[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};

void espNowAESBroadcastRecv(const uint8_t *data, int len) {
  if (len > 0) {
    Serial.println((const char*)data);
  }
}

void setup() {
  Serial.begin(115200);
  //Set device in AP mode to begin with
  espNowAESBroadcast_RecvCB(espNowAESBroadcastRecv);
  espNowAESBroadcast_begin(ESP_NOW_CHANNEL);
  espNowAESBroadcast_secredkey(secredKey);
  espNowAESBroadcast_setToBatteryNode();
}

void loop() {
  static unsigned long m = millis();

  //Ask instant sync from master.
  espNowAESBroadcast_requestInstantTimeSyncFromMaster();
  while (espNowAESBroadcast_isSyncedWithMaster() == false);
  char message[] = "SLAVE(12) HELLO MESSAGE";
  espNowAESBroadcast_send((uint8_t*)message, sizeof(message), 0); //set ttl to 3
  espNowAESBroadcast_loop();
  ESP.deepSleep(60000, WAKE_RF_DEFAULT); //Wakeup every minute
}
```
## Send message and get reply:
Send "MARCO" to other nodes
```c++

#include <EspNowAESBroadcast.h>

#define ESP_NOW_CHANNEL 1
//AES 128bit
unsigned char secredKey[] = {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE, 0xFF};

void espNowAESBroadcastRecv(const uint8_t *data, int len, uint32_t replyPrt){
}

void setup() {
  Serial.begin(115200);
  //Set device in AP mode to begin with
  espNowAESBroadcast_RecvCB(espNowAESBroadcastRecv);
  espNowAESBroadcast_secredkey(secredKey);
  espNowAESBroadcast_begin(ESP_NOW_CHANNEL);
  espNowAESBroadcast_setToMasterRole(true,3); //Set ttl to 3.
  espNowAESBroadcast_ErrorDebugCB([](int level, const char *str) {
    Serial.println(str);
  });
}

void loop() {
  static unsigned long m = millis();
  if(m+5000<millis()) {
    char message2[] = "MARCO";
    espNowAESBroadcast_sendAndHandleReply((uint8_t*)message2, sizeof(message2),3,[](const uint8_t *data, int len){
        if(len>0) { //Handle reply from other node
          Serial.print("Reply: "); //Prinst POLO. 
          Serial.println((const char*)data);
        }
    });
    m = millis();
  }
  espNowAESBroadcast_loop();
  delay(10);
}
```
Answer to "MARCO" and send "POLO"
```c++
#include <EspNowAESBroadcast.h>

#define ESP_NOW_CHANNEL 1
//AES 128bit
unsigned char secredKey[] = {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE, 0xFF};

void espNowAESBroadcastRecv(const uint8_t *data, int len, uint32_t replyPrt){
  if(len>0) {
    if(replyPrt) { //Reply asked. Send reply
        char m[]="POLO";
        Serial.println((char*)data); //Prints MARCO
        espNowAESBroadcast_sendReply((uint8_t*)m, sizeof(m), 0, replyPrt); //Special function for reply messages. Only the sender gets this message.
    } else {
      //No reply asked... All others messages are handled in here. 
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
  espNowAESBroadcast_ErrorDebugCB([](int level, const char *str) {
    Serial.println(str);
  });
  while (espNowAESBroadcast_isSyncedWithMaster() == false);
}

void loop() {
  espNowAESBroadcast_loop();
  delay(10);
}
```
