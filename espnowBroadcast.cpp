#ifdef ESP32
    #include <esp_now.h>
    #include <WiFi.h>
#else
    #include <ESP8266WiFi.h>
    #include <Esp.h>
    #include <espnow.h>
  #define ESP_OK 0
#endif
#include "espnowBroadcast.h"

const unsigned char broadcast_mac[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
bool init_done = false;
void(*espnowCB)(const uint8_t *, int) = NULL;

#ifdef ESP32
void esp_msg_recv_cb(const uint8_t *mac_addr, const uint8_t *data, int len)
#else
void esp_msg_recv_cb(u8 *mac_addr, u8 *data, u8 len)
#endif
{
  if(espnowCB!=NULL)
    espnowCB(data,len);
}
#ifdef ESP32
static void msg_send_cb(const uint8_t* mac, esp_now_send_status_t sendStatus)
{}
#else
static void msg_send_cb(u8* mac, u8 status)
{}
#endif
void espnowBroadcast_begin(int channel){
  WiFi.disconnect();

  WiFi.mode(WIFI_STA);

  if (esp_now_init() != 0)
  {
    return;
  }
  esp_now_register_recv_cb(esp_msg_recv_cb);
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
    esp_now_set_self_role(ESP_NOW_ROLE_SLAVE);
    esp_now_add_peer((u8*)broadcast_mac, ESP_NOW_ROLE_SLAVE, channel, NULL, 0);
  #endif
  // Set up callback
  init_done = true;
}

void espnowBroadcast_send(const uint8_t *d, int len){
  if(init_done==false) {
    Serial.println("espnowBroadcast not initialized");
    return;
  }
  #ifdef ESP32
    esp_now_send(broadcast_mac, (uint8_t*)(d), len);
  #else
    esp_now_send((u8*)broadcast_mac, (u8*)(d), len);
  #endif
}
void espnowBroadcast_cb(void(*cb)(const uint8_t *, int)){
  espnowCB = cb;
}
