#ifndef ESP_NOBRADCAST_H
#define ESP_NOBRADCAST_H

#define USE_RAW_801_11

#ifndef USE_RAW_801_11
  #ifdef ESP32
  #include <esp_now.h>
  #else
  #include <espnow.h>
  #endif
#endif

//#define DISABLE_CRYPTING //send messages as plain text
//#define DEBUG_PRINTS
#define MAX_ALLOWED_TIME_DIFFERENCE_IN_MESSAGES 3 //if message time differens more than this from RTC, reject message

    #ifndef USE_RAW_801_11
    void espNowFloodingMesh_begin(int channel);
    #else
    void espNowFloodingMesh_begin(int channel, char bsId[6]);
    #endif

    void espNowFloodingMesh_end();

    void espNowFloodingMesh_setChannel(int channel);

    void espNowFloodingMesh_setToMasterRole(bool master=true, unsigned char ttl=0 /*ttl for sync messages*/);
    void espNowFloodingMesh_setToBatteryNode(bool isBatteryNode=true);

    void espNowFloodingMesh_RecvCB(void (*callback)(const uint8_t *, int, uint32_t));
    void espNowFloodingMesh_send(uint8_t* msg, int size, int ttl=0); //Max message length is 236byte
    void espNowFloodingMesh_secredkey(const unsigned char key[16]);
    void espNowFloodingMesh_setAesInitializationVector(const unsigned char iv[16]);

    void espNowFloodingMesh_ErrorDebugCB(void (*callback)(int,const char *));

    uint32_t espNowFloodingMesh_sendAndHandleReply(uint8_t* msg, int size, int ttl, void (*f)(const uint8_t *, int)); //Max message length is 236byte

    //Run this only in Mainloop!!!
    bool espNowFloodingMesh_sendAndWaitReply(uint8_t* msg, int size, int ttl, int tryCount=1, void (*f)(const uint8_t *, int)=NULL, int timeoutMs=3000, int expectedCountOfReplies=1); //Max message length is 236byte
    bool espNowFloodingMesh_syncWithMasterAndWait(int timeoutMs=3000, int tryCount=3);

    void espNowFloodingMesh_sendReply(uint8_t* msg, int size, int ttl, uint32_t replyIdentifier);

    void espNowFloodingMesh_loop();

    void espNowFloodingMesh_delay(unsigned long tm);
    int espNowFloodingMesh_getTTL();

    void espNowFloodingMesh_setRTCTime(time_t time);
    time_t espNowFloodingMesh_getRTCTime();
#endif
