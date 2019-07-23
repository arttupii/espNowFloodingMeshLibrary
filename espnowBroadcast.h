#ifndef espnowBroadcast_H
#define espnowBroadcast_H
#include <Arduino.h>

void espnowBroadcast_begin(int channel);
void espnowBroadcast_send(const uint8_t *d, int len);
void espnowBroadcast_cb(void(*cb)(const uint8_t *, int));

#endif
