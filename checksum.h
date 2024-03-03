#ifndef CHECKSUM_H
#define CHECKSUM_H

/*
The checksum is usually stored at length + 2 
eg: *(unsigned int*)(requestServerListPacket+18) = Checksum(requestServerListPacket, 2, 16);
*/
unsigned int Checksum(unsigned char* packet, int offset, int length);

#endif