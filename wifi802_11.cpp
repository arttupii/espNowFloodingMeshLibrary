#include"wifi802_11.h"
#ifdef ESP32
#include <WiFi.h>
#include "esp_wifi.h"
#include <esp_wifi_types.h>
#include <esp_interface.h>
#else
#include <ESP8266WiFi.h>
#include <user_interface.h>
#endif
#include<Arduino.h>

const char *ssid = "MESH_NETWORK";
char wifi_password[20];

#define BEACON_SSID_OFFSET 38
#define SRCADDR_OFFSET 10
#define BSSID_OFFSET 16
#define MY_MAC_OFFSET 10
#define SEQNUM_OFFSET 22
#define DATA_START_OFFSET 24

uint8_t raw_HEADER[] = {
  //MAC HEADER
  0x40, 0x0C,             // 0-1: Frame Control  //Version 0 && Data Frame && MESH
  0x00, 0x00,             // 2-3: Duration
  0xaa, 0xbb, 0xcc, 0xee, 0xff, 0x11,       // 4-9: Destination address (broadcast)
  0xba, 0xde, 0xaf, 0xfe, 0x00, 0x06,       // 10-15: Source address
  0xba, 0xde, 0xaf, 0xfe, 0x00, 0x06,       // 16-21: BSSID
  0x00, 0x00             // 22-23: Sequence / fragment number
};
short sequence = 0;
void(*wifi_802_receive_callback)(const uint8_t *, int, uint8_t) = NULL;

#ifdef ESP32
void receive_raw_cb(void *recv_buf, wifi_promiscuous_pkt_type_t type) {
  /*
  20:35:41.710 ->            BF 20 24 80 00 00 00 00 A1 00 01 B6 AC 32 16 00 __$__________2__
  20:35:41.710 ->            93 0A 06 22 00 00 60 63 24 40 02 00 40 0C 00 00 ___"__`c$@__@___
  20:35:41.710 ->            FF FF FF FF FF FF BA DE AF FE 00 06 BA DE AF FE ________________
  20:35:41.710 ->            00 06 81 03 00 06 48 45 4C 4C 4F 32 D0 8D 3D 6A ______HELLO2__=j
  20:35:41.710 ->            78 56 AD BA E5 A8 FB 3F 9C BC FB 3F AD BA AD BA xV_____?___?____
  20:35:41.743 ->            E5 A8 FB 3F 9C BC FB 3F 00 00 00 00 00 00 00 00 ___?___?________
  20:35:41.743 ->            00 00 00 00 ____
  20:35:41.743 ->                    Length: 100

  */
  wifi_promiscuous_pkt_t *sniffer = (wifi_promiscuous_pkt_t *)recv_buf;
  if(sniffer->payload[0]!=0x40) return;
  if(memcmp(sniffer->payload+BSSID_OFFSET,raw_HEADER+BSSID_OFFSET, 6)!=0) return;

  unsigned char *d = sniffer->payload+DATA_START_OFFSET;
  short length = ((unsigned short)d[0])<<8 | d[1];

  wifi_802_receive_callback(d+2, length,sniffer->rx_ctrl.rssi);

  return;
}
#else
void receive_raw_cb(unsigned char*frm, short unsigned int len) {
  /*
    16:34:05.795 ->            C3 10 26 50 00 00 00 00 00 00 01 00 [40 0C 00 00 __&P________@___
    16:34:05.795 ->            FF FF FF FF FF FF BA DE AF FE 00 [06] BA DE AF FE ________________
    16:34:05.795 ->            00 06 00 00 48 65 6C 6C 6F 20 31 35 32 37 00 00 ____Hello_1527__
    16:34:05.828 ->            00 00 01 08 8B 96 82 84 0C 18 30 60 03 01 01 05 __________0`____
    16:34:05.828 ->            05 01 02 00 00 00 07 06 43 4E 00 01 0D 14 2A 01 ________CN____*_
    16:34:05.828 ->            00 32 04 6C 12 24 48 30 18 01 00 00 0F AC 02 02 _2_l_$H0________
    16:34:05.828 ->            00 00 0F AC ____
    16:34:05.828 ->                    Length: 100
  */
  uint8_t rssi = frm[0];
  //if(frm[0]!=0x40) return;

  if(frm[12]!=0x40) return;
  if(memcmp(frm+BSSID_OFFSET+12,raw_HEADER+BSSID_OFFSET, 6)!=0) return;
  unsigned char *d = frm+12+DATA_START_OFFSET;

  short length = ((unsigned short)d[0])<<8 | d[1];

  if(wifi_802_receive_callback!=NULL) {
    wifi_802_receive_callback(d+2, length, rssi);
  }
}
#endif
char password[15];
void wifi_802_11_begin(char bsId[], int channel){
  //WiFi.begin();
  String mac = WiFi.macAddress();
  memcpy(raw_HEADER+BSSID_OFFSET, bsId, 6);
  memcpy(raw_HEADER+MY_MAC_OFFSET, mac.c_str(), 6);

  #ifdef ESP32
  esp_wifi_set_mode(WIFI_MODE_STA);
  esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
  esp_wifi_set_promiscuous_rx_cb(receive_raw_cb);
  esp_wifi_set_promiscuous(1);
  esp_wifi_set_max_tx_power(127);
  #else
  wifi_set_opmode(STATION_MODE);
  wifi_set_channel(channel);
  wifi_set_promiscuous_rx_cb(receive_raw_cb);
  wifi_promiscuous_enable(true);
  WiFi.setOutputPower(20.5);
  #endif
}

void wifi_802_receive_cb(void(*cb)(const uint8_t *, int, uint8_t)) {
    wifi_802_receive_callback = cb;
}

void wifi_802_11_send(const uint8_t *d, int len) {
  uint8_t buf[500];
  for(int i=0;i<5;i++){
  if(len>sizeof(buf)-sizeof(raw_HEADER)-2) return;

  memcpy(buf,raw_HEADER, sizeof(raw_HEADER));
  memcpy(buf+sizeof(raw_HEADER)+2, d, len);
  memcpy(buf+SEQNUM_OFFSET,(char*)&sequence, 2);

  buf[sizeof(raw_HEADER)]=(len>>8)&0xff;
  buf[sizeof(raw_HEADER)+1]=len&0xff;


    #ifdef ESP32
    esp_wifi_80211_tx(ESP_IF_WIFI_STA, buf, sizeof(raw_HEADER) + len+ 2, true);
    #else
    wifi_send_pkt_freedom(buf, sizeof(raw_HEADER) + len+ 2, true);
    #endif
    sequence++;
  }
}
