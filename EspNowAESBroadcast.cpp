#ifdef ESP32
  #include <esp_now.h>
  #include <WiFi.h>
  #include <rom/crc.h>
  #include "mbedtls/aes.h"
#else
  #include <ESP8266WiFi.h>
  #include <Esp.h>
  #include <espnow.h>
  #include "AESLib.h"
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

bool masterFlag = false;
bool syncronized = false;
uint8_t syncTTL = 0;

time_t time_fix_value;

struct broadcast_header{
  uint8_t msgId;
  uint8_t length;
  uint8_t ttl;
  uint16_t crc16;
  time_t time;
};

const unsigned char broadcast_mac[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
uint8_t aes_secredKey[] = {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE, 0xFF};

bool sendMsg(uint8_t* msg, int size, int ttl, int msgId, time_t specificTime=0);
void hexDump(const uint8_t*b,int len);
void (*espNowAESBroadcast_receive_cb)(const uint8_t *, uint8_t *, int) = NULL;
uint16_t calculateCRC(int c, const unsigned char*b,int len);
int decryptBlock(const uint8_t *key, const uint8_t *from, uint8_t *to);

uint16_t calculateCRCWithoutTTL(uint8_t *msg) {
  struct broadcast_header *header = (struct broadcast_header*)msg;
  uint8_t ttl = header->ttl;
  uint16_t crc = header->crc16;

  header->ttl = 0;
  header->crc16 = 0;
  uint16_t ret = calculateCRC(0, msg, header->length+sizeof(struct broadcast_header));
  header->ttl = ttl;
  header->crc16 = crc;
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
  if(espNowAESBroadcast_receive_cb) {
    uint8_t disposableKey[DISPOSABLE_KEY_LENGTH];
    int block=0;
    {
      decryptBlock(aes_secredKey, data, disposableKey);
      block++;
    }
    unsigned char buffer[AES_BLOCK_SIZE*AES_BLOCKS_IN_MSG];
    for(;block<AES_BLOCKS_IN_MSG;block++){
      decryptBlock(disposableKey, data+block*AES_BLOCK_SIZE, buffer+(block-1)*AES_BLOCK_SIZE);
    }


    struct broadcast_header *header = (struct broadcast_header*)buffer;
    unsigned char *data = buffer + sizeof(struct broadcast_header);

    if(header->length>=0 && header->length<(AES_BLOCK_SIZE*AES_BLOCKS_IN_MSG)){
      uint16_t crc = header->crc16;
      header->crc16 = 0;
      uint16_t crc16 = calculateCRC(0, buffer, header->length + sizeof(struct broadcast_header));
      //hexDump(data,len);
      //#ifdef DEBUG_PRINTS
      //Serial.print("REC:"); Serial.println(crc16,HEX);
      //hexDump(buffer,header->length + sizeof(struct broadcast_header));
      //#endif

      #ifdef DEBUG_PRINTS
      Serial.print("CRC: ");Serial.print(crc16);Serial.print(" "),Serial.println(crc);
      #endif
        if(crc16==crc) {
          if(isMessageInRejectedList(buffer)) {
            Serial.print("Message is already handled. Skip it\n");
            return;
          }
          addMessageToRejectedList(buffer);

          uint8_t *b = (unsigned char*)malloc(header->length);
          memcpy(b, buffer + sizeof(struct broadcast_header), header->length);

          time_t currentTime = getRTCTime();
          bool ok = false;
          //Serial.print("MESSAGE ID");Serial.println(header->msgId);

          if(header->msgId==USER_MSG) {
            if(compareTime(currentTime,header->time,MAX_ALLOWED_TIME_DIFFERENCE_IN_MESSAGES)) {
              espNowAESBroadcast_receive_cb(mac_addr, b, header->length);
              ok = true;
            } else {
              Serial.print("Reject message because of time difference:");Serial.print(currentTime);Serial.print(" ");Serial.println(header->time);
              hexDump(buffer,  header->length + sizeof(struct broadcast_header));
            }
          }
          if(header->msgId==INSTANT_TIME_SYNC_REQ) {
            ok = true;
            if(masterFlag) {
              Serial.println("Send time sync message!! (Requested)");
              sendMsg(NULL, 0, 0, SYNC_TIME_MSG);
            }
          }
          if(header->msgId==SYNC_TIME_MSG) {
            if(masterFlag) {
              //only slaves can be syncronized
              return;
            }
            static time_t last_time_sync = 0;
            if(last_time_sync<header->time || ALLOW_TIME_ERROR_IN_SYNC_MESSAGE) {
              ok = true;
              last_time_sync = header->time;
              Serial.println("TIME SYNC MSG");

              Serial.print("Current time: "); Serial.println(asctime(localtime(&currentTime)));
              setRTCTime(header->time);
              currentTime = getRTCTime();
              Serial.print("New time: "); Serial.println(asctime(localtime(&currentTime)));
              Serial.print("New time (EPOC): "); Serial.println(currentTime);
              syncronized = true;
            }
          }

          if(ok && header->ttl) {
            //Serial.println("TTL");
            sendMsg(buffer + sizeof(struct broadcast_header), header->length, header->ttl-1, header->msgId, header->time);
          }
      }
      else {
        Serial.print("CRC: ");Serial.print(crc16);Serial.print(" "),Serial.println(crc);

        for(int i=0;i<header->length;i++){
          Serial.print("0x");Serial.print(data[i],HEX);Serial.print(",");
        }
        Serial.println();
      }
    } else {
      Serial.print("Invalis message received:"); Serial.println(0,HEX);
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
      Serial.println("Send success");
      break;

    case ESP_NOW_SEND_FAIL:
      Serial.println("Send Failure");
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
      Serial.println("Send success");
      break;

    default:
      Serial.println("Send Failure");
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

int decryptBlock(const uint8_t *key, const uint8_t *from, uint8_t *to) {
  #ifdef DISABLE_CRYPTING
  memcpy((void*)to,(void*)from,16);
  return 0;
  #else
  #ifdef ESP32
  mbedtls_aes_context aes;
  mbedtls_aes_init( &aes );
  mbedtls_aes_setkey_enc( &aes, key, 128 );
  int ret = mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_DECRYPT, from, to);
  mbedtls_aes_free(&aes);
  return ret;
  #else
    AESLib aesLib;
    byte aes_iv[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    aesLib.decrypt((char*)from, (char*)to, (byte*)key, aes_iv);
  #endif
  #endif
}

void encryptBlock(unsigned char *key, const unsigned char *from, unsigned char *to) {
#ifdef DISABLE_CRYPTING
  memcpy((void*)to,(void*)from,16);
  return;
 #else
    #ifdef ESP32
    mbedtls_aes_context aes;
    mbedtls_aes_init( &aes );
    mbedtls_aes_setkey_enc( &aes, key, 128 );
    mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_ENCRYPT, from, to);
    mbedtls_aes_free(&aes);
    #else
    AESLib aesLib;
    byte aes_iv[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    aesLib.encrypt((char*)from, (char*)to, (byte*)key, aes_iv);
    #endif
  #endif
}

bool sendMsg(uint8_t* msg, int size, int ttl, int msgId, time_t specificTime) {
  unsigned char data[AES_BLOCKS_IN_MSG*AES_BLOCK_SIZE];
  unsigned char disposableKey[DISPOSABLE_KEY_LENGTH];


  char block=0;

  if(size>=(sizeof(data)-sizeof(struct broadcast_header) - sizeof(disposableKey))) {
    Serial.println("espNowAESBroadcast_send: Invalid size");
    return false;
  }
  //Init disposable secred key for rest of blocks
  for(int i=0;i<sizeof(disposableKey);i++){
    disposableKey[i]=(uint8_t)random(0, 255);
  }
/*
  disposableKey[0] = '0';
  disposableKey[1] = '1';
  disposableKey[2] = '2';
  disposableKey[3] = '3';
  disposableKey[4] = '4';
  disposableKey[5] = '5';
  disposableKey[6] = '6';
  disposableKey[7] = '7';
  disposableKey[8] = '8';
  disposableKey[9] = '9';
  disposableKey[10] = 'A';
  disposableKey[11] = 'B';
  disposableKey[12] = 'C';
  disposableKey[13] = 'D';
  disposableKey[14] = 'E';
  disposableKey[15] = 'F';
*/

  struct broadcast_header *header= (struct broadcast_header*)data;
  memset(header,0x00,sizeof(struct broadcast_header)); //fill
  header->length = size;
  header->crc16 = 0;
  header->msgId = msgId;
  header->ttl= ttl;
  if(specificTime>0) {
    header->time = specificTime;
  } else {
    header->time = getRTCTime();
  }
  if(msg!=NULL){
    memcpy(data + sizeof(struct broadcast_header), msg, size);
  }
  uint16_t crc = calculateCRC(0, data, size + sizeof(struct broadcast_header));
  header->crc16 = crc;

  unsigned char encryptedData[AES_BLOCKS_IN_MSG*AES_BLOCK_SIZE];

  //encrypt disposableKey
  encryptBlock(aes_secredKey, disposableKey, encryptedData);

  int b;
  int data_i=0;
  int encrypted_i=AES_BLOCK_SIZE;
  for(b=0;b<AES_BLOCKS_IN_MSG;b++) {
    encryptBlock(disposableKey, data+data_i, encryptedData+encrypted_i);
    if((b*AES_BLOCK_SIZE)>=(size+sizeof(struct broadcast_header)+AES_BLOCK_SIZE)) {
      break;
    }
    data_i+=AES_BLOCK_SIZE;
    encrypted_i+=AES_BLOCK_SIZE;
  }
  addMessageToRejectedList(data);
  #ifdef ESP32
    esp_err_t status = esp_now_send(broadcast_mac, (uint8_t*)(encryptedData), AES_BLOCK_SIZE*b);
  #else
    int status = esp_now_send((u8*)broadcast_mac, (u8*)(encryptedData), AES_BLOCK_SIZE*b);
  #endif
  if (ESP_OK != status) {
      Serial.println("Error sending message");
      return false;
  }
  //#ifdef DEBUG_PRINTS
  //Serial.println("SEND:");

  //hexDump(data,AES_BLOCK_SIZE*b);
//  #endif
  return true;
}

bool espNowAESBroadcast_send(uint8_t* msg, int size, int ttl)  {
   return sendMsg(msg, size, ttl, USER_MSG);
}
