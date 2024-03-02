#ifndef BLOWFISH_H
#define BLOWFISH_H

void Blowfish_Initialize(unsigned char* key);
void Blowfish_Encipher(unsigned char* plaintext, unsigned int length);
void Blowfish_Decipher(unsigned char* ciphertext, unsigned int length);

#endif