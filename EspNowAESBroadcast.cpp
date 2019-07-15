#ifdef ESP32
  #include <esp_now.h>
  #include <WiFi.h>
  #include <rom/crc.h>
  #include "mbedtls/aes.h"
#else
  #include <ESP8266WiFi.h>
  #include <Esp.h>
  #include <espnow.h>
  #include "AESLib.h" //From https://github.com/kakopappa/arduino-esp8266-aes-lib
  #define ESP_OK 0
#endif
#include "EspNowAESBroadcast.h"
#include <time.h>

#define AES_BLOCK_SIZE  16
#define AES_BLOCKS_IN_MSG 15
#define DISPOSABLE_KEY_LENGTH AES_BLOCK_SIZE
#define REJECTED_LIST_SIZE 100

#define ALLOW_TIME_ERROR_IN_SYNC_MESSAGE false //Decrease secure. false=Validate sync messages against own RTC time


#define RESEND_SYNC_TIME_MS 10000

#define USER_MSG 1
#define SYNC_TIME_MSG 2
#define INSTANT_TIME_SYNC_REQ 3

unsigned char ivKey[16] = {0xb2, 0x4b, 0xf2, 0xf7, 0x7a, 0xc5, 0xec, 0x0c, 0x5e, 0x1f, 0x4d, 0xc1, 0xae, 0x46, 0x5e, 0x75};

bool masterFlag = false;
bool syncronized = false;
bool batteryNode = false;
uint8_t syncTTL = 0;

time_t time_fix_value;

struct header{
uint8_t msgId;
uint8_t length;
uint32_t randomNoise1;
uint32_t randomNoise2;
uint8_t ttl;
uint16_t crc16;
time_t time;
};
struct broadcast_header{
  struct header header;
  uint8_t data[240];
};

const unsigned char broadcast_mac[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
uint8_t aes_secredKey[] = {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE, 0xFF};

bool sendMsg(uint8_t* msg, int size, int ttl, int msgId, time_t specificTime=0);
void hexDump(const uint8_t*b,int len);
void (*espNowAESBroadcast_receive_cb)(const uint8_t *, uint8_t *, int) = NULL;
uint16_t calculateCRC(int c, const unsigned char*b,int len);
int decrypt(uint8_t *key, const uint8_t *from, unsigned char *to, int size);

void espNowAESBroadcast_setToBatteryNode(bool isBatteryNode) {
  batteryNode = isBatteryNode;
}
uint16_t calculateCRCWithoutTTL(uint8_t *msg) {
  struct broadcast_header *m = (struct broadcast_header*)msg;
  uint8_t ttl = m->header.ttl;
  uint16_t crc = m->header.crc16;

  m->header.ttl = 0;
  m->header.crc16 = 0;
  uint16_t ret = calculateCRC(0, msg, m->header.length+sizeof(struct header));
  m->header.ttl = ttl;
  m->header.crc16 = crc;
  return ret;
}

uint16_t rejectedMsgList[REJECTED_LIST_SIZE];
void addMessageToRejectedList(uint8_t *msg) {
  struct broadcast_header *header = (struct broadcast_header*)msg;

  static int index=0;
  uint16_t crc = calculateCRCWithoutTTL(msg);
  for(int i=0;i<REJECTED_LIST_SIZE;i++){
    if(rejectedMsgList[i]==crc) {
      return;
    }
  }
  rejectedMsgList[index] = crc;
  index++;
  if(index>=REJECTED_LIST_SIZE) {
    index=0;
  }
}

bool isMessageInRejectedList(uint8_t *msg) {
  uint16_t crc = calculateCRCWithoutTTL(msg);
  for(int i=0;i<REJECTED_LIST_SIZE;i++){
    if(rejectedMsgList[i]==crc) {
      return true;
    }
  }
  return false;
}

void espNowAESBroadcast_RecvCB(void (*callback)(const uint8_t *, uint8_t *, int)){
  espNowAESBroadcast_receive_cb = callback;
}

void espNowAESBroadcast_loop(){
  if(masterFlag) {
      static unsigned long start = millis();
      unsigned long elapsed = millis()-start;
      if(elapsed>=RESEND_SYNC_TIME_MS) { //10s
        start = millis();
        Serial.println("Send time sync message!!");
        sendMsg(NULL, 0, 0, SYNC_TIME_MSG);
      }
  }
}
void espNowAESBroadcast_setToMasterRole(bool master, unsigned char ttl){
  masterFlag = master;
  syncTTL = ttl;
}
uint16_t calculateCRC(int c, const unsigned char*b,int len) {
  #ifdef ESP32
    return crc16_le(0, b, len);
  #else
    //Copied from https://www.lammertbies.nl/forum/viewtopic.php?t=1528
    uint16_t crc = 0xFFFF;
    int i;
    if (len) do {
    crc ^= *b++;
    for (i=0; i<8; i++) {
      if (crc & 1) crc = (crc >> 1) ^ 0x8408;
      else crc >>= 1;
    }
    } while (--len);
    return(~crc);
  #endif
}

void hexDump(const uint8_t*b,int len){
Serial.println();
  for(int i=0;i<len;i=i+16) {
    Serial.print("           ");
    for(int x=0;x<16&&(x+i)<len;x++) {
      if(b[i+x]<=0xf) Serial.print("0");
      Serial.print(b[i+x],HEX);
      Serial.print(" ");
    }
    printf("   ");
    for(int x=0;x<16&&(x+i)<len;x++) {
      if(b[i+x]<=32||b[i+x]>=126) {
          Serial.print("_");
      } else Serial.print((char)b[i+x]);
    }
    Serial.print("\n");
  }
  Serial.print("                   Length: ");
  Serial.println(len);
}

#ifdef ESP32
void setRTCTime(time_t time) {
  struct timeval now = { .tv_sec = time };
  settimeofday(&now, NULL);
}
time_t getRTCTime() {
  return time(NULL);
}
#else
long long rtcFixValue = 0;
void setRTCTime(time_t t) {
  long long newTime = t;
  long long currentTime = time(NULL);
  rtcFixValue = newTime-currentTime;
}
time_t getRTCTime() {
  long long currentTime = time(NULL);
  long long fixedTime = currentTime + rtcFixValue;
  return fixedTime;
}
#endif

bool compareTime(time_t current, time_t received, time_t maxDifference) {
  if(current<received) {
    return ((received-current) <= maxDifference);
  } else {
    return ((current-received) <= maxDifference);
  }
  return false;
}

bool espNowAESBroadcast_isSyncedWithMaster() {
  if(masterFlag) return true;
  espNowAESBroadcast_loop();
  if(syncronized) {
    syncronized = false;
    return true;
  }
  delay(1);
  return false;
}

#ifdef ESP32
void msg_recv_cb(const uint8_t *mac_addr, const uint8_t *data, int len)
#else
void msg_recv_cb(u8 *mac_addr, u8 *data, u8 len)
#endif
{
  if(len>=sizeof(struct broadcast_header)) return;
  if(espNowAESBroadcast_receive_cb) {
    struct broadcast_header m;
    //Serial.println("R:");
    //hexDump(data,len);

    decrypt(aes_secredKey, data, (uint8_t*)&m, len);

    if(m.header.length>=0 && m.header.length < (sizeof(m.data) ) ){
      uint16_t crc = m.header.crc16;
      int messageLengtWithHeader = m.header.length + sizeof(struct header);
      m.header.crc16 = 0;
      uint16_t crc16 = calculateCRC(0, (uint8_t*)&m, messageLengtWithHeader);
      //hexDump((uint8_t*)&m, len);
      //#ifdef DEBUG_PRINTS
      //Serial.print("REC:"); Serial.println(crc16,HEX);
      //hexDump(buffer,m.header.length + sizeof(struct broadcast_header));
      //#endif

      #ifdef DEBUG_PRINTS
      Serial.print("CRC: ");Serial.print(crc16);Serial.print(" "),Serial.println(crc);
      #endif
        if(crc16==crc) {
          if(isMessageInRejectedList((uint8_t*)&m)) {
            Serial.print("Message is already handled. Skip it\n");
            return;
          }
          addMessageToRejectedList((uint8_t*)&m);

          uint8_t *b = (unsigned char*)malloc(m.header.length);
          memcpy(b, m.data, m.header.length);

          time_t currentTime = getRTCTime();
          bool ok = false;
          //Serial.print("MESSAGE ID");Serial.println(header->msgId);

          if(m.header.msgId==USER_MSG) {
            if(compareTime(currentTime,m.header.time,MAX_ALLOWED_TIME_DIFFERENCE_IN_MESSAGES)) {
              espNowAESBroadcast_receive_cb(mac_addr, b, m.header.length);
              ok = true;
            } else {
              Serial.print("Reject message because of time difference:");Serial.print(currentTime);Serial.print(" ");Serial.println(m.header.time);
              hexDump((uint8_t*)&m,  messageLengtWithHeader);
            }
          }
          if(m.header.msgId==INSTANT_TIME_SYNC_REQ) {
            ok = true;
            if(masterFlag) {
              Serial.println("Send time sync message!! (Requested)");
              sendMsg(NULL, 0, 0, SYNC_TIME_MSG);
            }
          }
          if(m.header.msgId==SYNC_TIME_MSG) {
            if(masterFlag) {
              //only slaves can be syncronized
              return;
            }
            static time_t last_time_sync = 0;
            if(last_time_sync<m.header.time || ALLOW_TIME_ERROR_IN_SYNC_MESSAGE) {
              ok = true;
              last_time_sync = m.header.time;
              Serial.println("TIME SYNC MSG");

              Serial.print("Current time: "); Serial.println(asctime(localtime(&currentTime)));
              setRTCTime(m.header.time);
              currentTime = getRTCTime();
              Serial.print("New time: "); Serial.println(asctime(localtime(&currentTime)));
              Serial.print("New time (EPOC): "); Serial.println(currentTime);
              syncronized = true;
            }
          }

          if(ok && m.header.ttl && batteryNode==false) {
            //Serial.println("TTL");
            sendMsg(m.data, m.header.length, m.header.ttl-1, m.header.msgId, m.header.time);
          }
      }
      else {
        Serial.print("CRC: ");Serial.print(crc16);Serial.print(" "),Serial.println(crc);

        for(int i=0;i<m.header.length;i++){
          Serial.print("0x");Serial.print(data[i],HEX);Serial.print(",");
        }
        Serial.println();
      }
    } else {
      Serial.print("Invalid message received:"); Serial.println(0,HEX);
      hexDump(data,len);
    }
  }
}
void espNowAESBroadcast_requestInstantTimeSyncFromMaster() {
  if(masterFlag) return;
  Serial.println("Request instant time sync from master.");
  sendMsg(NULL, 0, 0, INSTANT_TIME_SYNC_REQ);
}
#ifdef ESP32
static void msg_send_cb(const uint8_t* mac, esp_now_send_status_t sendStatus)
{
  switch (sendStatus)
  {
    case ESP_NOW_SEND_SUCCESS:
      //Serial.println("Send success");
      break;

    case ESP_NOW_SEND_FAIL:
      //Serial.println("Send Failure");
      break;

    default:
      break;
  }
}
#else
static void msg_send_cb(u8* mac, u8 status)
{
  switch (status)
  {
    case ESP_OK:
      //Serial.println("Send success");
      break;

    default:
      //Serial.println("Send Failure");
      break;
  }
}
#endif




//   void setSendCb(function<void(void)> f)
void espNowAESBroadcast_begin(int channel) {
  WiFi.disconnect();

  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  if (esp_now_init() != 0)
  {
    return;
  }


  #ifdef ESP32
    esp_now_peer_info_t peer_info;
    peer_info.channel = channel;
    memcpy(peer_info.peer_addr, broadcast_mac, sizeof(broadcast_mac));
    peer_info.ifidx = ESP_IF_WIFI_STA;
    peer_info.encrypt = false;
    esp_err_t status = esp_now_add_peer(&peer_info);
    if (ESP_OK != status)
    {
      Serial.println("Could not add peer");
    }
  #else
    randomSeed(analogRead(0));
    esp_now_set_self_role(ESP_NOW_ROLE_SLAVE);
    esp_now_add_peer((u8*)broadcast_mac, ESP_NOW_ROLE_SLAVE, channel, NULL, 0);
    int status;
  #endif
  // Set up callback
  status = esp_now_register_recv_cb(msg_recv_cb);
  if (ESP_OK != status)
  {
    Serial.println("Could not register callback");
  }

  status = esp_now_register_send_cb(msg_send_cb);
  if (ESP_OK != status)
  {
    Serial.println("Could not register send callback");
  }
  for(int i=0;i<REJECTED_LIST_SIZE;i++) {
    rejectedMsgList[i]=0;
  }
}

void espNowAESBroadcast_secredkey(const unsigned char key[16]){
  memcpy(aes_secredKey, key, sizeof(aes_secredKey));
}
int decrypt(uint8_t *key, const uint8_t *from, unsigned char *to, int size) {
  #ifdef DISABLE_CRYPTING
  memcpy((void*)to,(void*)from,size);
  return 0;
  #else
    #ifdef ESP32
      unsigned char iv[16];
      memcpy(iv,ivKey,sizeof(iv));

      mbedtls_aes_context aes;
      mbedtls_aes_init( &aes );
      mbedtls_aes_setkey_enc( &aes, key, 128 );
      esp_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, size, iv, from, to);
      mbedtls_aes_free(&aes);
    #else
      byte iv[16];
      memcpy(iv,ivKey,sizeof(iv));
      AES aesLib;
      aesLib.set_key( (byte *)key , sizeof(key));
      aesLib.do_aes_decrypt((byte *)from,size , to, key, 128, iv);
    #endif
  #endif
}

void encrypt(unsigned char *key, const unsigned char *from, unsigned char *to, int size) {
 #ifdef DISABLE_CRYPTING
  memcpy((void*)to,(void*)from,size);
  return;
 #else
    #ifdef ESP32
     unsigned char iv[16];
     memcpy(iv,ivKey,sizeof(iv));

     mbedtls_aes_context aes;
     mbedtls_aes_init( &aes );
     mbedtls_aes_setkey_enc( &aes, key, 128 );
     esp_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, size, iv, from, to);
     mbedtls_aes_free(&aes);
    #else
      byte iv[16];
      memcpy(iv,ivKey,sizeof(iv));
      AES aesLib;
      aesLib.set_key( (byte *)key , sizeof(key));
      aesLib.do_aes_encrypt((byte *)from,size , to, key, 128, iv);
    #endif
  #endif
}

bool sendMsg(uint8_t* msg, int size, int ttl, int msgId, time_t specificTime) {
  if(size>=sizeof(struct broadcast_header)) {
    Serial.println("espNowAESBroadcast_send: Invalid size");
    return false;
  }

  struct broadcast_header m;
  memset(&m,0x00,sizeof(struct broadcast_header)); //fill
  m.header.length = size;
  m.header.crc16 = 0;
  m.header.msgId = msgId;
  m.header.ttl= ttl;
  #ifdef ESP32
    m.header.randomNoise1 = esp_random();
    m.header.randomNoise1 = esp_random();
  #else
    m.header.randomNoise1 = random(0, 2147483647);
    m.header.randomNoise1 = random(0, 2147483647);
  #endif

  if(specificTime>0) {
    m.header.time = specificTime;
  } else {
    m.header.time = getRTCTime();
  }
  if(msg!=NULL){
    memcpy(m.data, msg, size);
  }

  uint16_t crc = calculateCRC(0, (uint8_t*)&m, size + sizeof(m.header));
//  Serial.print("CCCCCCCCCCCCCCCC ");Serial.println(crc);
  m.header.crc16 = crc;

  unsigned char encryptedData[AES_BLOCKS_IN_MSG*AES_BLOCK_SIZE];

  int dataSizeToSend = ((size + sizeof(m.header))/16+1)*16;
  for(int i=size + sizeof(m.header);i<dataSizeToSend;i++) {
    #ifdef ESP32
    ((unsigned char*)&m)[i]=esp_random();
    #else
    ((unsigned char*)&m)[i]=random(0, 255);
    #endif
  }
//  hexDump( (unsigned char *)&m, dataSizeToSend);
  encrypt(aes_secredKey, (const unsigned char *)&m, encryptedData, dataSizeToSend);

//  Serial.print("CCCCCCCCCCCCCCCC1 ");Serial.println(m.header.crc16);
//  hexDump((uint8_t*)(encryptedData), dataSizeToSend);
/*
  int esp_aes_crypt_cbc( esp_aes_context *ctx,
                     int mode,
                     size_t length,
                     unsigned char iv[16],
                     const unsigned char *input,
                     unsigned char *output );
*/

  addMessageToRejectedList((uint8_t *)&m);
//  Serial.print("CCCCCCCCCCCCCCCC2 ");Serial.println(m.header.crc16);
//  hexDump((uint8_t*)(encryptedData), dataSizeToSend);

  #ifdef ESP32
    esp_err_t status = esp_now_send(broadcast_mac, (uint8_t*)(encryptedData), dataSizeToSend);
  #else
    int status = esp_now_send((u8*)broadcast_mac, (u8*)(encryptedData), dataSizeToSend);
  #endif
  if (ESP_OK != status) {
      Serial.println("Error sending message");
      return false;
  }
  //#ifdef DEBUG_PRINTS
//  Serial.println("SEND:");

//  hexDump((uint8_t*)(encryptedData), dataSizeToSend);
//  #endif
  return true;
}

bool espNowAESBroadcast_send(uint8_t* msg, int size, int ttl)  {
   return sendMsg(msg, size, ttl, USER_MSG);
}
