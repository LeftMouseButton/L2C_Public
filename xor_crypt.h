#ifndef XOR_CRYPT_H
#define XOR_CRYPT_H

void GamePacket_Encrypt(unsigned char* packet, unsigned short packetLength, unsigned char* key);
void GamePacket_Decrypt(unsigned char* packet, unsigned short packetLength, unsigned char* key);

#endif