#ifdef ESP32
  #ifndef USE_RAW_801_11
    #include <esp_now.h>
    #include <WiFi.h>
  #endif
  #include <rom/crc.h>
  #include "mbedtls/aes.h"
#else
#include <ESP8266WiFi.h>
#include "AESLib.h" //From https://github.com/kakopappa/arduino-esp8266-aes-lib
#endif
#include "AESLib.h" //From https://github.com/kakopappa/arduino-esp8266-aes-lib

#ifndef USE_RAW_801_11
    #include "espnowBroadcast.h"
#endif
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
int myBsid = 0x112233;

#pragma pack(push,1)

struct header{
uint8_t msgId;
uint8_t length;
uint32_t p1;
uint8_t ttl;
uint16_t crc16;
time_t time;
};

struct mesh_secred_frame{
  struct header header;
  uint8_t data[240];
};
typedef struct{
  unsigned char b[3];
  void set(uint32_t v) {
      b[0]=(v>>(16))&0xff;
      b[1]=(v>>(8))&0xff;
      b[2]=v&0xff;
  }
   void set(const uint8_t *v) {
      memcpy(b,v,sizeof(b));
  }
  uint32_t operator=(const uint32_t& b) {
      set(b);
      return b;
  }
  bool operator==(const uint32_t bsId) {
      return bsId==get();
  }
  uint32_t get(){
      uint32_t ret=0;
      ret|=((uint32_t)b[0])<<16;
      ret|=((uint32_t)b[1])<<8;
      ret|=((uint32_t)b[2]);
      return ret;
  }
}bsid_t;

struct meshFrame{
  bsid_t bsid;
  struct mesh_secred_frame secred;
};
#pragma pack(pop);
int espNowFloodingMesh_getTTL() {
    return syncTTL;
}
const unsigned char broadcast_mac[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
uint8_t aes_secredKey[] = {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE, 0xFF};
bool forwardMsg(struct meshFrame *m);
uint32_t sendMsg(uint8_t* msg, int size, int ttl, int msgId, void *ptr=NULL);
void hexDump(const uint8_t*b,int len);
static void (*espNowFloodingMesh_receive_cb)(const uint8_t *, int, uint32_t) = NULL;

uint16_t calculateCRC(int c, const unsigned char*b,int len);
uint16_t calculateCRC(struct meshFrame *m);
int decrypt(const uint8_t *_from, struct meshFrame *m, int size);
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
  void addMessageToRejectedList(struct meshFrame *m) {
    uint16_t crc = calculateCRCWithoutTTL(m);

    for(int i=0;i<REJECTED_LIST_SIZE;i++){
      if(rejectedMsgList[i]==crc) {
        if(ttlList[i]<m->secred.header.ttl) {
          ttlList[i] = m->secred.header.ttl;
        }
        return;
      }
    }
    rejectedMsgList[index] = crc;
    ttlList[index] = m->secred.header.ttl;

    index++;
    if(index>=REJECTED_LIST_SIZE) {
      index=0;
    }
  }

  bool isMessageInRejectedList(struct meshFrame *m) {
    uint16_t crc = calculateCRCWithoutTTL(m);
    for(int i=0;i<REJECTED_LIST_SIZE;i++){
      if(rejectedMsgList[i]==crc) {
        if(ttlList[i]>=m->secred.header.ttl) {
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
    uint16_t calculateCRCWithoutTTL(struct meshFrame *m) {
      uint8_t ttl = m->secred.header.ttl;
      m->secred.header.ttl = 0;
      uint16_t ret = calculateCRC(m);
      m->secred.header.ttl = ttl;
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
        sendMsg(NULL, 0, syncTTL, SYNC_TIME_MSG);
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
  delay(1);
}
void espNowFloodingMesh_setToMasterRole(bool master, unsigned char ttl){
  masterFlag = master;
  syncTTL = ttl;
}
uint16_t calculateCRC(int c, const unsigned char*b,int len) {
  #ifdef ESP32JJJ
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

uint16_t calculateCRC(struct meshFrame *m){
  uint16_t crc = m->secred.header.crc16;
  m->secred.header.crc16 = 0;
  int size = m->secred.header.length + sizeof(m->secred.header);
  uint16_t ret = calculateCRC(0, (const unsigned char*)m + sizeof(bsid_t),size);
  m->secred.header.crc16 = crc;
  return ret;
}

void hexDump(const uint8_t*b,int len){
  //#ifdef DEBUG_PRINTS
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
//  #endif
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
  void msg_recv_cb(const uint8_t *data, int len)
#endif
{
  #ifdef DEBUG_PRINTS
  Serial.print("REC[RAW]:");
  hexDump((uint8_t*)data,len);
  #endif
  struct meshFrame m;
  m.bsid.set(data);

  if(myBsid!=m.bsid.get()) {
    Serial.println(myBsid, HEX);
    Serial.println(m.bsid.get(), HEX);

    return;
  }
  if(len>=sizeof(struct meshFrame)) return;

    //memset(&m,0,sizeof(m));
    decrypt((const uint8_t*)data, &m, len);
#ifdef DEBUG_PRINTS
    Serial.print("REC:");
    hexDump((uint8_t*)&m,m.secred.header.length + sizeof(m.secred.header)+3);
#endif
    if(!(m.secred.header.msgId==USER_MSG||m.secred.header.msgId==SYNC_TIME_MSG||m.secred.header.msgId==INSTANT_TIME_SYNC_REQ
      ||m.secred.header.msgId==USER_REQUIRE_RESPONSE_MSG||m.secred.header.msgId==USER_REQUIRE_REPLY_MSG)) {
        //Quick wilter;
        return;
    }
    if(m.secred.header.length>=0 && m.secred.header.length < (sizeof(m.secred.data) ) ){
      uint16_t crc = m.secred.header.crc16;
      int messageLengtWithHeader = m.secred.header.length + sizeof(struct header);
      uint16_t crc16 = calculateCRC(&m);

        #ifdef DEBUG_PRINTS
        Serial.print("REC:");
        hexDump((uint8_t*)&m,messageLengtWithHeader);
        #endif

        bool messageTimeOk = true;
        time_t currentTime = espNowFloodingMesh_getRTCTime();

        if(crc16==crc) {

          if(!compareTime(currentTime,m.secred.header.time, MAX_ALLOWED_TIME_DIFFERENCE_IN_MESSAGES)) {
              messageTimeOk = false;
              print(1,"Received message with invalid time stamp.");
            //  Serial.print("CurrentTime:");Serial.println(currentTime);
            //  Serial.print("ReceivedTime:");Serial.println(m.secred.header.time);
          }

          if(rejectedMessageDB.isMessageInRejectedList(&m)) {
            //Serial.println("Message already handed");
            return;
          }
          rejectedMessageDB.addMessageToRejectedList(&m);

          bool ok = false;

          if(espNowFloodingMesh_receive_cb) {
            if( m.secred.header.msgId==USER_MSG) {
              if(messageTimeOk) {
                espNowFloodingMesh_receive_cb(m.secred.data, m.secred.header.length, 0);
                ok = true;
              } else {
                #ifdef DEBUG_PRINTS
                Serial.print("Reject message because of time difference:");Serial.print(currentTime);Serial.print(" ");Serial.println(m.secred.header.time);
                hexDump((uint8_t*)&m,  messageLengtWithHeader);
                #endif
              }
            }

            if( m.secred.header.msgId==USER_REQUIRE_REPLY_MSG) {
              if(messageTimeOk) {
                const struct requestReplyDbItem* d = requestReplyDB.getCallback(m.secred.header.p1);
                if(d!=NULL){
                  d->cb(m.secred.data, m.secred.header.length);
                } else {
                  espNowFloodingMesh_receive_cb(m.secred.data, m.secred.header.length, m.secred.header.p1);
                }
                ok = true;
              } else {
                #ifdef DEBUG_PRINTS
                Serial.print("Reject message because of time difference:");Serial.print(currentTime);Serial.print(" ");Serial.println(m.secred.header.time);
                hexDump((uint8_t*)&m,  messageLengtWithHeader);
                #endif
                print(1,"Message rejected because of time difference.");
              }
            }

            if(m.secred.header.msgId==USER_REQUIRE_RESPONSE_MSG) {
              if(messageTimeOk) {
                espNowFloodingMesh_receive_cb(m.secred.data, m.secred.header.length, m.secred.header.p1);
                ok = true;
              } else {
                #ifdef DEBUG_PRINTS
                Serial.print("Reject message because of time difference:");Serial.print(currentTime);Serial.print(" ");Serial.println(m.secred.header.time);
                hexDump((uint8_t*)&m,  messageLengtWithHeader);
                #endif
                print(1,"Message rejected because of time difference.");
              }
            }
          }
          if(m.secred.header.msgId==INSTANT_TIME_SYNC_REQ) {
            ok = true;
            if(masterFlag) {
              #ifdef DEBUG_PRINTS
              Serial.println("Send time sync message!! (Requested)");
              #endif
              sendMsg(NULL, 0, syncTTL, SYNC_TIME_MSG);
              //print(3,"Send time sync message!! (Requested)");
            }
          }
          if(m.secred.header.msgId==SYNC_TIME_MSG) {
            if(masterFlag) {
              //only slaves can be syncronized
              return;
            }
            static time_t last_time_sync = 0;
            Serial.print("Last sync time:"); Serial.println(last_time_sync);
            Serial.print("Sync time in message:"); Serial.println(m.secred.header.time);

            if(last_time_sync<m.secred.header.time || ALLOW_TIME_ERROR_IN_SYNC_MESSAGE) {
              ok = true;
              last_time_sync = m.secred.header.time;
            //  #ifdef DEBUG_PRINTS
              Serial.println("TIME SYNC MSG");
              //currentTime = espNowFloodingMesh_getRTCTime();

              Serial.print("Current time: "); Serial.print(asctime(localtime(&currentTime)));
            //  #endif
              espNowFloodingMesh_setRTCTime(m.secred.header.time);
          //    #ifdef DEBUG_PRINTS
              currentTime = espNowFloodingMesh_getRTCTime();
              Serial.print("    New time: "); Serial.print(asctime(localtime(&currentTime)));
          //    #endif
              syncronized = true;
              print(3,"Time syncronised with master");
            }
          }

          if(ok && m.secred.header.ttl && batteryNode==false) {
            //Serial.println("TTL");
            //delay(1);
            forwardMsg(&m);
          }
      } else {
      #ifdef DEBUG_PRINTS
        Serial.print("#CRC: ");Serial.print(crc16);Serial.print(" "),Serial.println(crc);
        for(int i=0;i<m.secred.header.length;i++){
          Serial.print("0x");Serial.print(data[i],HEX);Serial.print(",");
        }
        Serial.println();
        hexDump((uint8_t*)&m,200);
        Serial.println();
        hexDump((uint8_t*)data,200);
       #endif
      }
    } else {
      #ifdef DEBUG_PRINTS
      Serial.print("Invalid message received:"); Serial.println(0,HEX);
      hexDump(data,len);
      #endif
    }
}
void espNowFloodingMesh_requestInstantTimeSyncFromMaster() {
  if(masterFlag) return;
  #ifdef DEBUG_PRINTS
  Serial.println("Request instant time sync from master.");
  #endif
  sendMsg(NULL, 0, 0, INSTANT_TIME_SYNC_REQ);
}

void espNowFloodingMesh_end() {
}


//   void setSendCb(function<void(void)> f)
#ifndef USE_RAW_801_11
void espNowFloodingMesh_begin(int channel, int bsid) {
#else
void espNowFloodingMesh_begin(int channel, char bsId[6]) {
#endif

  #ifndef ESP32
    randomSeed(analogRead(0));
  #endif

  #ifndef USE_RAW_801_11
      espnowBroadcast_cb(msg_recv_cb);
      espnowBroadcast_begin(channel);
  #else
        wifi_802_11_begin(bsId, channel);
        wifi_802_receive_cb(msg_recv_cb);
  #endif
  isespNowFloodingMeshInitialized=true;

  myBsid = bsid;
}

void espNowFloodingMesh_secredkey(const unsigned char key[16]){
  memcpy(aes_secredKey, key, sizeof(aes_secredKey));
}

int decrypt(const uint8_t *_from, struct meshFrame *m, int size) {
  unsigned char iv[16];
  memcpy(iv,ivKey,sizeof(iv));

  uint8_t to[2*16];
  for(int i=0;i<size;i=i+16) {
      const uint8_t *from = _from + i + sizeof(bsid_t);
      uint8_t *key = aes_secredKey;

      #ifdef DISABLE_CRYPTING
        memcpy(to,from,16);
      #else
        #ifdef ESP32

          esp_aes_context ctx;
          esp_aes_init( &ctx );
          esp_aes_setkey( &ctx, key, 128 );
          esp_aes_acquire_hardware ();
          esp_aes_crypt_cbc(&ctx, ESP_AES_DECRYPT, 16, iv, from, to);
          esp_aes_release_hardware ();
          esp_aes_free(&ctx);

        #else
          AES aesLib;
          aesLib.set_key( (byte *)key , sizeof(key));
          aesLib.do_aes_decrypt((byte *)from,16 , to, key, 128, iv);
        #endif
      #endif

      if((i+sizeof(bsid_t)+16)<=sizeof(m->secred)) {
        memcpy((uint8_t*)m+i+sizeof(bsid_t), to, 16);
      }
  }
}

int encrypt(struct meshFrame *m) {
  int size = ((m->secred.header.length + sizeof(m->secred.header))/16)*16+16;
  unsigned char iv[16];
  memcpy(iv,ivKey,sizeof(iv));
  uint8_t to[2*16];

  for(int i=0;i<size;i=i+16) {
      uint8_t *from = (uint8_t *)&m->secred+i;
      uint8_t *key = aes_secredKey;
     #ifdef DISABLE_CRYPTING
       memcpy((void*)to,(void*)from,16);
     #else
        #ifdef ESP32
         esp_aes_context ctx;
         esp_aes_init( &ctx );
         esp_aes_setkey( &ctx, key, 128 );
         esp_aes_acquire_hardware();
         esp_aes_crypt_cbc(&ctx, ESP_AES_ENCRYPT, 16, iv, from, to);
         esp_aes_release_hardware();
         esp_aes_free(&ctx);
        #else
          AES aesLib;
          aesLib.set_key( (byte *)key , sizeof(key));
          aesLib.do_aes_encrypt((byte *)from, size , (uint8_t *)&m->secred, key, 128, iv);
          break;
        #endif
      #endif
      memcpy((uint8_t*)m+i+sizeof(bsid_t), to, 16);
  }
/*
  for(int i=m->secred.header.length + sizeof(m->secred.header)+1;i<size;i++) {
    #ifdef ESP32
    ((unsigned char*)&m->secred.header)[i]=esp_random();
    #else
    ((unsigned char*)&m->secred.header)[i]=random(0, 255);
    #endif
  }*/

  return size + sizeof(bsid_t);
}

bool forwardMsg(struct meshFrame *m) {
  if(m->secred.header.ttl==0) return false;

  //struct meshFrame mesh;
  //memcpy(&mesh,&m, sizeof(mesh));
  m->secred.header.ttl= m->secred.header.ttl-1;
  m->secred.header.crc16 = calculateCRC(m);

  int dataToCryptSize = ((m->secred.header.length + sizeof(m->secred.header))/16)*16;

  rejectedMessageDB.addMessageToRejectedList(m);

  int size = encrypt(m);

  #ifdef DEBUG_PRINTS
  Serial.print("FORWARD:");
  hexDump((const uint8_t*)m, size);
  #endif

  #ifdef USE_RAW_801_11
      wifi_802_11_send((uint8_t*)(m), size);
  #else
      espnowBroadcast_send((uint8_t*)m, size);
  #endif
  return true;
}


uint32_t sendMsg(uint8_t* msg, int size, int ttl, int msgId, void *ptr) {
  uint32_t ret=0;
  if(size>=sizeof(struct mesh_secred_frame)) {
    #ifdef DEBUG_PRINTS
    Serial.println("espNowFloodingMesh_send: Invalid size");
    #endif
    return false;
  }

  static struct meshFrame m;
  memset(&m,0x00,sizeof(struct meshFrame)); //fill
  m.secred.header.length = size;
  m.secred.header.crc16 = 0;
  m.secred.header.msgId = msgId;
  m.secred.header.ttl= ttl;
  m.bsid.set(myBsid);
  #ifdef ESP32
    m.secred.header.p1 = esp_random();
  #else
    m.secred.header.p1 = random(0, 0xffffffff);
  #endif

  m.secred.header.time = espNowFloodingMesh_getRTCTime();

  if(msg!=NULL){
    memcpy(m.secred.data, msg, size);
  }

  if(msgId==USER_REQUIRE_RESPONSE_MSG) {
    m.secred.header.p1 = requestReplyDB.calculateMessageIdentifier();
    ret = m.secred.header.p1;
    requestReplyDB.add(m.secred.header.p1, (void (*)(const uint8_t*, int))ptr);
    //Serial.print("Send request with "); Serial.println(m.secred.header.p1);
  } if(msgId==USER_REQUIRE_REPLY_MSG && ptr!=NULL) {
    m.secred.header.p1 = *((uint32_t*)ptr);
  }

  m.secred.header.crc16 = calculateCRC(&m);
  #ifdef DEBUG_PRINTS
   Serial.print("Send0:");
   hexDump((const uint8_t*)&m, size+20);
  #endif
  rejectedMessageDB.addMessageToRejectedList(&m);

  int sendSize = encrypt(&m);

/*
struct meshFrame mm;
Serial.print("--->:");
decrypt((const uint8_t*)&m, &mm, sendSize);
Serial.print("--->:");
hexDump((const uint8_t*)&mm, size+20);
Serial.print("--->:");
*/

   #ifdef DEBUG_PRINTS
    Serial.print("Send[RAW]:");
    hexDump((const uint8_t*)&m, sendSize);
  #endif

  #ifdef USE_RAW_801_11
      wifi_802_11_send((uint8_t*)&m, sendSize);
  #else
      espnowBroadcast_send((uint8_t*)&m, sendSize);
  #endif
  return ret;
}

void espNowFloodingMesh_send(uint8_t* msg, int size, int ttl)  {
   sendMsg(msg, size, ttl, USER_MSG);
}

void espNowFloodingMesh_sendReply(uint8_t* msg, int size, int ttl, uint32_t replyIdentifier)  {
   sendMsg(msg, size, ttl, USER_REQUIRE_REPLY_MSG, (void*)&replyIdentifier);
}

uint32_t espNowFloodingMesh_sendAndHandleReply(uint8_t* msg, int size, int ttl, void (*f)(const uint8_t *, int)) {
  return sendMsg(msg, size, ttl, USER_REQUIRE_RESPONSE_MSG, (void*)f);
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
