//Encrypts the packet in-place
void GamePacket_Encrypt(unsigned char* packet, unsigned short packetLength, unsigned char* key)
{
	unsigned char* _packet = packet+2;
	unsigned char temp = 0;

	for (int i = 0; i < packetLength-2; i++)
	{
		temp ^= _packet[i] ^ key[i & 15];
		_packet[i] = temp;
	}

	*(unsigned int*)(key+8) += packetLength-2;
}

//Derypts the packet in-place
void GamePacket_Decrypt(unsigned char* packet, unsigned short packetLength, unsigned char* key)
{
	unsigned char* _packet = packet+2;
	unsigned char temp = 0, temp2;

	for (int i = 0; i < packetLength-2; i++)
	{
		temp2 = _packet[i];
		_packet[i] ^= key[i & 15] ^ temp;
		temp = temp2;
	}

	*(unsigned int*)(key+8) += packetLength-2;
}