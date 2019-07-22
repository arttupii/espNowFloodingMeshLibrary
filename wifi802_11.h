#ifndef WIFI_802_11_h__
#define WIFI_802_11_h__
#include <Arduino.h>

void wifi_802_11_begin(char bsId[], int channel);
void wifi_802_11_send(const uint8_t *d, int len);
void wifi_802_receive_cb(void(*cb)(const uint8_t *, int, uint8_t));

#endif
