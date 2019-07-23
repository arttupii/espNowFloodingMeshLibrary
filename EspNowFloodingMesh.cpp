#ifdef ESP32
  #ifndef USE_RAW_801_11
    #include <esp_now.h>
    #include <WiFi.h>
  #endif
  #include <rom/crc.h>
  #include "mbedtls/aes.h"
#else
#ifndef USE_RAW_801_11
    #include <ESP8266WiFi.h>
    #include <Esp.h>
    #include <espnow.h>
  #endif
  #define ESP_OK 0
#endif
#include "AESLib.h" //From https://github.com/kakopappa/arduino-esp8266-aes-lib

#include "EspNowFloodingMesh.h"
#include <time.h>
#ifdef USE_RAW_801_11
#include "wifi802_11.h"
#endif
#define AES_BLOCK_SIZE  16
#define DISPOSABLE_KEY_LENGTH AES_BLOCK_SIZE
#define REJECTED_LIST_SIZE 50
#define REQUEST_REPLY_DATA_BASE_SIZE 20

#define ALLOW_TIME_ERROR_IN_SYNC_MESSAGE false //Decrease secure. false=Validate sync messages against own RTC time


#define RESEND_SYNC_TIME_MS 10000

#define USER_MSG 1
#define SYNC_TIME_MSG 2
#define INSTANT_TIME_SYNC_REQ 3
#define USER_REQUIRE_RESPONSE_MSG 4
#define USER_REQUIRE_REPLY_MSG 5


unsigned char ivKey[16] = {0xb2, 0x4b, 0xf2, 0xf7, 0x7a, 0xc5, 0xec, 0x0c, 0x5e, 0x1f, 0x4d, 0xc1, 0xae, 0x46, 0x5e, 0x75};

bool masterFlag = false;
bool syncronized = false;
bool batteryNode = false;
uint8_t syncTTL = 0;
bool isespNowFloodingMeshInitialized = false;
time_t time_fix_value;

struct header{
uint8_t msgId;
uint8_t length;
uint32_t p1;
uint8_t ttl;
uint16_t crc16;
time_t time;
};

struct broadcast_header{
  struct header header;
  uint8_t data[240];
};

int espNowFloodingMesh_getTTL() {
    return syncTTL;
}
const unsigned char broadcast_mac[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
uint8_t aes_secredKey[] = {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE, 0xFF};
bool forwardMsg(struct broadcast_header &m);
uint32_t sendMsg(uint8_t* msg, int size, int ttl, int msgId, time_t specificTime=0, void *ptr=NULL);
void hexDump(const uint8_t*b,int len);
static void (*espNowFloodingMesh_receive_cb)(const uint8_t *, int, uint32_t) = NULL;

uint16_t calculateCRC(int c, const unsigned char*b,int len);
int decrypt(uint8_t *key, const uint8_t *from, unsigned char *to, int size);
bool compareTime(time_t current, time_t received, time_t maxDifference);



void (*errorPrintCB)(int,const char *) = NULL;

void espNowFloodingMesh_ErrorDebugCB(void (*callback)(int, const char *)){
    errorPrintCB = callback;
}

void print(int level, const char * format, ... )
{

 if(errorPrintCB){
      static char buffer[256];
      va_list args;
      va_start (args, format);
      vsprintf (buffer,format, args);

      errorPrintCB(level, buffer);

      va_end (args);
  }
}


void espNowFloodingMesh_setAesInitializationVector(const unsigned char iv[16]) {
  memcpy(ivKey, iv, sizeof(ivKey));
}

void espNowFloodingMesh_setToBatteryNode(bool isBatteryNode) {
  batteryNode = isBatteryNode;
}

struct requestReplyDbItem{
    void (*cb)(const uint8_t *, int);
    uint32_t messageIdentifierCode;
    time_t time;
    uint8_t ttl;
};
class RequestReplyDataBase{
public:
  RequestReplyDataBase(){
    index=0;
    memset(db, 0,sizeof(db));
    c=1;
  }
  ~RequestReplyDataBase(){}
  void add(uint32_t messageIdentifierCode, void (*f)(const uint8_t *, int)) {
    db[index].cb = f;
    db[index].messageIdentifierCode = messageIdentifierCode;
    db[index].time = espNowFloodingMesh_getRTCTime();
    index++;
    if(index>=REQUEST_REPLY_DATA_BASE_SIZE) {
      index = 0;
    }
  }
  uint32_t calculateMessageIdentifier() {
    String mac = WiFi.macAddress();
    uint32_t ret = calculateCRC(0, (const uint8_t*)mac.c_str(), 6);
    #ifdef ESP32
      ret = ret<<8 | (esp_random()&0xff);
    #else
      ret = ret<<8 | (random(0, 0xff)&0xff);
    #endif
    ret = ret<<8 | c++;
    if(c==0) { c=1; } //messageIdentifier is never zero
    return ret;
  }
  const struct requestReplyDbItem* getCallback(uint32_t messageIdentifierCode) {
    time_t currentTime = espNowFloodingMesh_getRTCTime();
    for(int i=0;i<REQUEST_REPLY_DATA_BASE_SIZE;i++) {
      if(db[i].messageIdentifierCode==messageIdentifierCode) {
        if(compareTime(currentTime, db[i].time, MAX_ALLOWED_TIME_DIFFERENCE_IN_MESSAGES)) {
            if(db[i].cb!=NULL) {
              return &db[i];
            }
        }
      }
    }
    return NULL;
  }
  void removeItem() {//Cleaning db  --> Remove the oldest item
    memset(&db[index],0,sizeof(struct requestReplyDbItem));
    index++;
    if(index>=REQUEST_REPLY_DATA_BASE_SIZE) {
      index=0;
    }
  }
private:
    struct requestReplyDbItem db[REQUEST_REPLY_DATA_BASE_SIZE];
    int index;
    uint8_t c;
};
RequestReplyDataBase requestReplyDB;

class RejectedMessageDB{
public:
  ~RejectedMessageDB() {}
  RejectedMessageDB() {
    memset(rejectedMsgList,0, sizeof(rejectedMsgList));
    memset(ttlList,0, sizeof(ttlList));
    index=0;
  }
  void removeItem() { //Cleaning db  --> Remove the oldest item
    rejectedMsgList[index] = 0;
    ttlList[index] = 0;
    index++;
    if(index>=REJECTED_LIST_SIZE) {
      index=0;
    }
  }
  void addMessageToRejectedList(uint8_t *msg) {
    struct broadcast_header *header = (struct broadcast_header*)msg;
    uint16_t crc = calculateCRCWithoutTTL(msg);

    for(int i=0;i<REJECTED_LIST_SIZE;i++){
      if(rejectedMsgList[i]==crc) {
        if(ttlList[i]<header->header.ttl) {
          ttlList[i] = header->header.ttl;
        }
        return;
      }
    }
    rejectedMsgList[index] = crc;
    ttlList[index] = header->header.ttl;

    index++;
    if(index>=REJECTED_LIST_SIZE) {
      index=0;
    }
  }

  bool isMessageInRejectedList(uint8_t *msg) {
    struct broadcast_header *header = (struct broadcast_header*)msg;
    uint16_t crc = calculateCRCWithoutTTL(msg);
    for(int i=0;i<REJECTED_LIST_SIZE;i++){
      if(rejectedMsgList[i]==crc) {
        if(ttlList[i]>=header->header.ttl) {
          return true;
        }
      }
    }
    return false;
  }
private:
    uint16_t rejectedMsgList[REJECTED_LIST_SIZE];
    uint8_t ttlList[REJECTED_LIST_SIZE];
    int index;
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
};
RejectedMessageDB rejectedMessageDB;


void espNowFloodingMesh_RecvCB(void (*callback)(const uint8_t *, int, uint32_t)){
  espNowFloodingMesh_receive_cb = callback;
}

void espNowFloodingMesh_delay(unsigned long tm) {
  for(int i=0;i<(tm/10);i++){
    espNowFloodingMesh_loop();
    delay(10);
  }
}

void espNowFloodingMesh_loop(){
  if(isespNowFloodingMeshInitialized==false) return;
  if(masterFlag) {
      static unsigned long start = 0;
      unsigned long elapsed = millis()-start;
      if(elapsed>=RESEND_SYNC_TIME_MS) { //10s
        start = millis();
        #ifdef DEBUG_PRINTS
        Serial.println("Send time sync message!!");
        #endif
        print(3,"Send time sync message.");
        sendMsg(NULL, 0, 0, SYNC_TIME_MSG);
      }
  }
  { //Clean data base
    static unsigned long dbtm = millis();
    unsigned long elapsed = millis()-dbtm;
    if(elapsed>=500) {
      dbtm = millis();
      requestReplyDB.removeItem();
      rejectedMessageDB.removeItem();
    }
  }
}
void espNowFloodingMesh_setToMasterRole(bool master, unsigned char ttl){
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
  #ifdef DEBUG_PRINTS
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
  #endif
}

#ifdef ESP32
void espNowFloodingMesh_setRTCTime(time_t time) {
  struct timeval now = { .tv_sec = time };
  settimeofday(&now, NULL);
    if(masterFlag){
        print(3, "Send time sync");
        sendMsg(NULL, 0, syncTTL, SYNC_TIME_MSG);
    }
}
time_t espNowFloodingMesh_getRTCTime() {
  return time(NULL);
}
#else
long long rtcFixValue = 0;
void espNowFloodingMesh_setRTCTime(time_t t) {
  long long newTime = t;
  long long currentTime = time(NULL);
  rtcFixValue = newTime-currentTime;

    if(masterFlag){
        print(3, "Send time sync");
        sendMsg(NULL, 0, syncTTL, SYNC_TIME_MSG);
    }
}
time_t espNowFloodingMesh_getRTCTime() {
  long long currentTime = time(NULL);
  long long fixedTime = currentTime + rtcFixValue;
  return fixedTime;
}
#endif

bool compareTime(time_t current, time_t received, time_t maxDifference) {
  if(current==received) return true;
  if(current<received) {
    return ((received-current) <= maxDifference);
  } else {
    return ((current-received) <= maxDifference);
  }
  return false;
}

#ifdef USE_RAW_801_11
void msg_recv_cb(const uint8_t *data, int len, uint8_t rssi)
#else
  #ifdef ESP32
  void msg_recv_cb(const uint8_t *mac_addr, const uint8_t *data, int len)
  #else
  void msg_recv_cb(u8 *mac_addr, u8 *data, u8 len)
  #endif
#endif
{
  Serial.print("RSSI:");
  Serial.println(rssi);
  #ifdef DEBUG_PRINTS
  Serial.print("REC[RAW]:");
  hexDump((uint8_t*)data,len);
  #endif

  if(len>=sizeof(struct broadcast_header)) return;

  if(espNowFloodingMesh_receive_cb) {
    struct broadcast_header m;

    decrypt(aes_secredKey, (const uint8_t*)data, (uint8_t*)&m, len);

    if(m.header.length>=0 && m.header.length < (sizeof(m.data) ) ){
      uint16_t crc = m.header.crc16;
      int messageLengtWithHeader = m.header.length + sizeof(struct header);
      m.header.crc16 = 0;
      uint16_t crc16 = calculateCRC(0, (uint8_t*)&m, messageLengtWithHeader);
      m.header.crc16 = crc;

        #ifdef DEBUG_PRINTS
        Serial.print("REC:");
        hexDump((uint8_t*)&m,messageLengtWithHeader);
        #endif

        bool messageTimeOk = true;
        time_t currentTime = espNowFloodingMesh_getRTCTime();
        if(!compareTime(currentTime,m.header.time,MAX_ALLOWED_TIME_DIFFERENCE_IN_MESSAGES)) {
            messageTimeOk = false;
            print(1,"Received message with invalid time stamp.");
            Serial.print("CurrentTime:");Serial.println(currentTime);
            Serial.print("ReceivedTime:");Serial.println(m.header.time);
        }

        if(crc16==crc) {
          bool isAlreadyHandled = rejectedMessageDB.isMessageInRejectedList((uint8_t*)&m);
          if(isAlreadyHandled) {
            return;
          }
          rejectedMessageDB.addMessageToRejectedList((uint8_t*)&m);

          bool ok = false;

          if( m.header.msgId==USER_MSG) {
            if(messageTimeOk) {
              espNowFloodingMesh_receive_cb(m.data, m.header.length, 0);
              ok = true;
            } else {
              #ifdef DEBUG_PRINTS
              Serial.print("Reject message because of time difference:");Serial.print(currentTime);Serial.print(" ");Serial.println(m.header.time);
              hexDump((uint8_t*)&m,  messageLengtWithHeader);
              #endif
            }
          }

          if( m.header.msgId==USER_REQUIRE_REPLY_MSG) {
            if(messageTimeOk) {
              const struct requestReplyDbItem* d = requestReplyDB.getCallback(m.header.p1);
              if(d!=NULL){
                d->cb(m.data, m.header.length);
              } else {
                espNowFloodingMesh_receive_cb(m.data, m.header.length, m.header.p1);
              }
              ok = true;
            } else {
              #ifdef DEBUG_PRINTS
              Serial.print("Reject message because of time difference:");Serial.print(currentTime);Serial.print(" ");Serial.println(m.header.time);
              hexDump((uint8_t*)&m,  messageLengtWithHeader);
              #endif
              print(1,"Message rejected because of time difference.");
            }
          }

          if(m.header.msgId==USER_REQUIRE_RESPONSE_MSG) {
            if(messageTimeOk) {
              espNowFloodingMesh_receive_cb(m.data, m.header.length, m.header.p1);
              ok = true;
            } else {
              #ifdef DEBUG_PRINTS
              Serial.print("Reject message because of time difference:");Serial.print(currentTime);Serial.print(" ");Serial.println(m.header.time);
              hexDump((uint8_t*)&m,  messageLengtWithHeader);
              #endif
              print(1,"Message rejected because of time difference.");
            }
          }
          if(m.header.msgId==INSTANT_TIME_SYNC_REQ) {
            ok = true;
            if(masterFlag) {
              #ifdef DEBUG_PRINTS
              Serial.println("Send time sync message!! (Requested)");
              #endif
              sendMsg(NULL, 0, syncTTL, SYNC_TIME_MSG);
              print(3,"Send time sync message!! (Requested)");
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
              #ifdef DEBUG_PRINTS
              Serial.println("TIME SYNC MSG");
              Serial.print("Current time: "); Serial.print(asctime(localtime(&currentTime)));
              #endif
              espNowFloodingMesh_setRTCTime(m.header.time);
              currentTime = espNowFloodingMesh_getRTCTime();
              #ifdef DEBUG_PRINTS
              Serial.print("New time: "); Serial.print(asctime(localtime(&currentTime)));
              #endif
              syncronized = true;
              print(3,"Time syncronised with master");
            }
          }

          if(ok && m.header.ttl && batteryNode==false) {
            //Serial.println("TTL");
            forwardMsg(m);
          }
      }
      else {
        #ifdef DEBUG_PRINTS
        Serial.print("CRC: ");Serial.print(crc16);Serial.print(" "),Serial.println(crc);
        for(int i=0;i<m.header.length;i++){
          Serial.print("0x");Serial.print(data[i],HEX);Serial.print(",");
        }
        Serial.println();
        #endif
      }
    } else {
      #ifdef DEBUG_PRINTS
      Serial.print("Invalid message received:"); Serial.println(0,HEX);
      hexDump(data,len);
      #endif
    }
  }
}
void espNowFloodingMesh_requestInstantTimeSyncFromMaster() {
  if(masterFlag) return;
  #ifdef DEBUG_PRINTS
  Serial.println("Request instant time sync from master.");
  #endif
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

void espNowFloodingMesh_end() {
  WiFi.disconnect();

  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  isespNowFloodingMeshInitialized=true;
}


//   void setSendCb(function<void(void)> f)
#ifndef USE_RAW_801_11
void espNowFloodingMesh_begin(int channel) {
#else
void espNowFloodingMesh_begin(int channel, char bsId[6]) {
#endif
  #ifndef USE_RAW_801_11
    WiFi.disconnect();

    WiFi.mode(WIFI_STA);

    if (esp_now_init() != 0)
    {
      return;
    }
    esp_now_register_recv_cb(msg_recv_cb);
    esp_now_register_send_cb(msg_send_cb);

    #ifdef ESP32
      static esp_now_peer_info_t slave;
      memset(&slave, 0, sizeof(slave));
      for (int ii = 0; ii < 6; ++ii) {
        slave.peer_addr[ii] = (uint8_t)0xff;
      }
      slave.channel = channel; // pick a channel
      slave.encrypt = 0; // no encryption

      const esp_now_peer_info_t *peer = &slave;
      const uint8_t *peer_addr = slave.peer_addr;
      esp_now_add_peer(peer);
    #else
      randomSeed(analogRead(0));
      esp_now_set_self_role(ESP_NOW_ROLE_SLAVE);
      esp_now_add_peer((u8*)broadcast_mac, ESP_NOW_ROLE_SLAVE, channel, NULL, 0);
      int status;
    #endif
    // Set up callback
  #else
    #ifndef ESP32
      randomSeed(analogRead(0));
    #endif
      wifi_802_11_begin(bsId, channel);
      wifi_802_receive_cb(msg_recv_cb);
  #endif

  isespNowFloodingMeshInitialized=true;
}

void espNowFloodingMesh_secredkey(const unsigned char key[16]){
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

      esp_aes_acquire_hardware ();
      esp_aes_context ctx;
      esp_aes_init( &ctx );
      esp_aes_setkey( &ctx, key, 128 );
      esp_aes_crypt_cbc(&ctx, ESP_AES_DECRYPT, size, iv, from, to);
      esp_aes_free(&ctx);
      esp_aes_release_hardware ();
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

     esp_aes_acquire_hardware ();
     esp_aes_context ctx;
     esp_aes_init( &ctx );
     esp_aes_setkey( &ctx, key, 128 );
     esp_aes_crypt_cbc(&ctx, ESP_AES_ENCRYPT, size, iv, from, to);
     esp_aes_free(&ctx);
     esp_aes_release_hardware ();

    #else
      byte iv[16];
      memcpy(iv,ivKey,sizeof(iv));
      AES aesLib;
      aesLib.set_key( (byte *)key , sizeof(key));
      aesLib.do_aes_encrypt((byte *)from,size , to, key, 128, iv);
    #endif
  #endif
}

bool forwardMsg(struct broadcast_header &m) {
   if(m.header.ttl==0) return false;
   m.header.ttl= m.header.ttl-1;
   m.header.crc16=0;

  uint16_t crc = calculateCRC(0, (uint8_t*)&m, m.header.length + sizeof(m.header));
  m.header.crc16 = crc;

  int dataSizeToSend = ((m.header.length + sizeof(m.header))/16)*16;
  unsigned char encryptedData[dataSizeToSend+AES_BLOCK_SIZE];

  for(int i=m.header.length + sizeof(m.header)+1;i<dataSizeToSend;i++) {
    #ifdef ESP32
    ((unsigned char*)&m)[i]=esp_random();
    #else
    ((unsigned char*)&m)[i]=random(0, 255);
    #endif
  }

  encrypt(aes_secredKey, (const unsigned char *)&m, encryptedData, dataSizeToSend);

  rejectedMessageDB.addMessageToRejectedList((uint8_t *)&m);

  #ifdef DEBUG_PRINTS
  Serial.print("FORWARD:");
  hexDump((const uint8_t*)&m, dataSizeToSend);
  #endif

  #ifdef USE_RAW_801_11
      wifi_802_11_send((uint8_t*)(encryptedData), dataSizeToSend);
  #else
    #ifdef ESP32
      esp_err_t status = esp_now_send(broadcast_mac, (uint8_t*)(encryptedData), dataSizeToSend);
    #else
      int status = esp_now_send((u8*)broadcast_mac, (u8*)(encryptedData), dataSizeToSend);
    #endif
    if (ESP_OK != status) {
        #ifdef DEBUG_PRINTS
        Serial.println("Error sending message");
        #endif
        return false;
    }
  #endif
  return true;
}


uint32_t sendMsg(uint8_t* msg, int size, int ttl, int msgId, time_t specificTime, void *ptr) {
  uint32_t ret=0;
  if(size>=sizeof(struct broadcast_header)) {
    #ifdef DEBUG_PRINTS
    Serial.println("espNowFloodingMesh_send: Invalid size");
    #endif
    return false;
  }

  struct broadcast_header m;
  memset(&m,0x00,sizeof(struct broadcast_header)); //fill
  m.header.length = size;
  m.header.crc16 = 0;
  m.header.msgId = msgId;
  m.header.ttl= ttl;
  #ifdef ESP32
    m.header.p1 = esp_random();
  #else
    m.header.p1 = random(0, 0xffffffff);
  #endif

  if(specificTime>0) {
    m.header.time = specificTime;
  } else {
    m.header.time = espNowFloodingMesh_getRTCTime();
  }
  if(msg!=NULL){
    memcpy(m.data, msg, size);
  }

  if(msgId==USER_REQUIRE_RESPONSE_MSG) {
    m.header.p1 = requestReplyDB.calculateMessageIdentifier();
    ret = m.header.p1;
    requestReplyDB.add(m.header.p1, (void (*)(const uint8_t*, int))ptr);
    //Serial.print("Send request with "); Serial.println(m.header.p1);
  } if(msgId==USER_REQUIRE_REPLY_MSG && ptr!=NULL) {
    m.header.p1 = *((uint32_t*)ptr);
  }


  uint16_t crc = calculateCRC(0, (uint8_t*)&m, size + sizeof(m.header));
  m.header.crc16 = crc;

  int dataSizeToSend = ((size + sizeof(m.header))/16+1)*16;

  unsigned char encryptedData[dataSizeToSend+AES_BLOCK_SIZE];

  for(int i=size + sizeof(m.header)+1;i<dataSizeToSend;i++) {
    #ifdef ESP32
    ((unsigned char*)&m)[i]=esp_random();
    #else
    ((unsigned char*)&m)[i]=random(0, 255);
    #endif
  }

  encrypt(aes_secredKey, (const unsigned char *)&m, encryptedData, dataSizeToSend);
  #ifdef DEBUG_PRINTS
  Serial.print("Send:");
  hexDump((const unsigned char *)&m, dataSizeToSend);
  #endif
   #ifdef DEBUG_PRINTS
    Serial.print("Send[RAW]:");
    hexDump((const uint8_t*)encryptedData, dataSizeToSend);
    #endif

  rejectedMessageDB.addMessageToRejectedList((uint8_t *)&m);


  #ifdef USE_RAW_801_11
      wifi_802_11_send((uint8_t*)(encryptedData), dataSizeToSend);
  #else
    #ifdef ESP32
      esp_err_t status = esp_now_send(broadcast_mac, (uint8_t*)(encryptedData), dataSizeToSend);
    #else
      int status = esp_now_send((u8*)broadcast_mac, (u8*)(encryptedData), dataSizeToSend);
    #endif
    if (ESP_OK != status) {
        #ifdef DEBUG_PRINTS
        Serial.println("Error sending message");
        #endif
        return false;
    }
  #endif
  return ret;
}

void espNowFloodingMesh_send(uint8_t* msg, int size, int ttl)  {
   sendMsg(msg, size, ttl, USER_MSG);
}

void espNowFloodingMesh_sendReply(uint8_t* msg, int size, int ttl, uint32_t replyIdentifier)  {
   sendMsg(msg, size, ttl, USER_REQUIRE_REPLY_MSG, 0,(void*)&replyIdentifier);
}

uint32_t espNowFloodingMesh_sendAndHandleReply(uint8_t* msg, int size, int ttl, void (*f)(const uint8_t *, int)) {
  return sendMsg(msg, size, ttl, USER_REQUIRE_RESPONSE_MSG, 0, (void*)f);
}

bool espNowFloodingMesh_sendAndWaitReply(uint8_t* msg, int size, int ttl, int tryCount, void (*f)(const uint8_t *, int), int timeoutMs, int expectedCountOfReplies){
  static int replyCnt=0;
  static void (*callback)(const uint8_t *, int);
  callback = f;

  for(int i=0;i<tryCount;i++) {
    espNowFloodingMesh_sendAndHandleReply(msg, size, ttl, [](const uint8_t *data, int len){
      if(callback!=NULL) {
        callback(data,len);
      }
      replyCnt++;
    });

    unsigned long dbtm = millis();

    while(1) {
      espNowFloodingMesh_loop();
      delay(10);
      if(expectedCountOfReplies<=replyCnt) {
        return true; //OK all received;
      }
      unsigned long elapsed = millis()-dbtm;
      if(elapsed>timeoutMs) {
        //timeout
        print(0, "Timeout: waiting replies");
        break;
      }
    }
  }
  return false;
}

bool espNowFloodingMesh_syncWithMasterAndWait(int timeoutMs, int tryCount) {
  if(masterFlag) return true;
  syncronized = false;
  for(int i=0;i<tryCount;i++) {
      unsigned long dbtm = millis();
      espNowFloodingMesh_requestInstantTimeSyncFromMaster();

      while(1) {
        espNowFloodingMesh_loop();
        delay(10);
        if(syncronized) {
          return true; //OK all received;
        }
        unsigned long elapsed = millis()-dbtm;
        if(elapsed>timeoutMs) {
          break;
        }
      }
  }
  return false;
}
