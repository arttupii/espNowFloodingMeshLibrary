#include<espnowBroadcast.h>

void rec(const uint8_t *d, int l){
  Serial.println((const char*)d);  
}
void setup() {
  Serial.begin(115200);
  // put your setup code here, to run once:
  espnowBroadcast_begin(1);
  espnowBroadcast_cb(rec);
}

void loop() {
  // put your main code here, to run repeatedly:
  delay(1000);
  Serial.println("Send");
  espnowBroadcast_send((const uint8_t*)"HELLO22", 6);
}
