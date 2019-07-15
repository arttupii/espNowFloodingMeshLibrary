#ifndef ESP_NOBRADCAST_H
#define ESP_NOBRADCAST_H
#ifdef ESP32
#include <esp_now.h>
#else
#include <espnow.h>
#endif

//#define DISABLE_CRYPTING //send messages as plain text
//#define DEBUG_PRINTS
#define MAX_ALLOWED_TIME_DIFFERENCE_IN_MESSAGES 3 //if message time differens more than this from RTC, reject message

    void espNowAESBroadcast_begin(int channel);

    void espNowAESBroadcast_setChannel(int channel);

    void espNowAESBroadcast_setToMasterRole(bool master=true, unsigned char ttl=0 /*ttl for sync messages*/);
    void espNowAESBroadcast_setToBatteryNode(bool isBatteryNode=true);

    void espNowAESBroadcast_RecvCB(void (*callback)(const uint8_t *, const uint8_t *, int));
    bool espNowAESBroadcast_send(uint8_t* msg, int size, int ttl=0); //Max message length is 236byte
    void espNowAESBroadcast_secredkey(const unsigned char key[16]);

    void espNowAESBroadcast_requestInstantTimeSyncFromMaster(); //Only battery devices should use this!!!
    bool espNowAESBroadcast_isSyncedWithMaster();
    void espNowAESBroadcast_loop();
#endif
