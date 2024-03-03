/*
The checksum is usually stored at length + 2 
eg: *(unsigned int*)(requestServerListPacket+18) = Checksum(requestServerListPacket, 2, 16);
*/
unsigned int Checksum(unsigned char* packet, int offset, int length)
{
	unsigned int checksum = 0;

	for (int i = offset; i < length; i += 4)
		checksum ^= *(unsigned int*)(packet+i);

	return checksum;
}