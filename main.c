#include <stdio.h>
#include <stdarg.h>
#include <pthread.h>
#include <netinet/in.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "blowfish.h"
#include "xor_crypt.h"
#include "checksum.h"
#include "rsa.h"

enum enumBotType
{
	Interception = 0,
	Emulation = 1
};
enum enumBotType BotType;
enum enumError
{
	NONE = 0x00,
	NETWORK_FATAL = 0x01
};
pthread_t interceptionThread_Server = 0;
pthread_t interceptionThread_Client = 0;
pthread_t emulationThread_Server = 0;
unsigned short clientToBotAuthPort = 2106;
unsigned short clientToBotGamePort = 7777;
int clientSocket_Auth = -1;
int clientSocket_Game = -1;
int serverSocket = -1;
char authServerIP[] = "127.0.0.1";
unsigned short authServerPort = 2107;
char gameServerIP[] = "127.0.0.1";
unsigned short gameServerPort = 7778;
char gameServerIPForVM[] = "192.168.156.1";
unsigned char receiveBuffer_Server[65535]; //recv packets into this buffer
unsigned char receiveBuffer_Client[65535]; //recv packets into this buffer
unsigned char staticBlowfishKey[16] = { 0x6B, 0x60, 0xCB, 0x5B, 0x82, 0xCE, 0x90, 0xB1, 0xCC, 0x2B, 0x6C, 0x55, 0x6C, 0x6C, 0x6C, 0x6C }; //found in game client
unsigned char gameKey_Encryption_Server[] = {0xB5, 0xCF, 0x18, 0xDE, 0xE8, 0x09, 0xB4, 0xDB, 0xC8, 0x27, 0x93, 0x01, 0xA1, 0x6C, 0x31, 0x97 };
unsigned char gameKey_Decryption_Server[] = {0xB5, 0xCF, 0x18, 0xDE, 0xE8, 0x09, 0xB4, 0xDB, 0xC8, 0x27, 0x93, 0x01, 0xA1, 0x6C, 0x31, 0x97 };
unsigned char gameKey_Encryption_Client[] = {0xB5, 0xCF, 0x18, 0xDE, 0xE8, 0x09, 0xB4, 0xDB, 0xC8, 0x27, 0x93, 0x01, 0xA1, 0x6C, 0x31, 0x97 };
unsigned char gameKey_Decryption_Client[] = {0xB5, 0xCF, 0x18, 0xDE, 0xE8, 0x09, 0xB4, 0xDB, 0xC8, 0x27, 0x93, 0x01, 0xA1, 0x6C, 0x31, 0x97 };
enum enumGameVersion
{
	C0_Prelude = 0x00,
	C1_HarbingersofWar = 0x01,
	C2_AgeOfSplendor = 0x02,
	C3_RiseOfDarkness = 0x03,
	C4_ScionsOfDestiny = 0x04,
	C5_OathOfBlood = 0x05,
	C6_Interlude = 0x06,
	CT1_Kamael = 0x07,
	CT1_5_Hellbound = 0x08,
	CT2_1_Gracia1 = 0x09,
	CT2_2_Gracia2 = 0x10,
	CT2_3_GraciaFinal = 0x11,
	CT2_4_GraciaEpilogue = 0x12,
	CT2_5_Freya = 0x13,
	CT2_6_HighFive = 0x14
	//plus ~20 other versions
};
enum enumGameVersion GameVersion;
int SessionKey_Init;
unsigned char rsaKey[128]; //used only for sending username/password to authserver.
enum enumLoginState
{
	LOGIN_AUTH = 0,
	LOGIN_GAME = 1
};
enum enumLoginState LoginState;
char username[14] = "username\0\0\0\0\0\0";
char password[16] = "pass\0\0\0\0\0\0\0\0\0\0\0\0";
unsigned long long SessionKey_LoginOK;
unsigned long long SessionKey_PlayOK;

//Wrapper for easy redirect/disable later
void Log(char* text, ...)
{
	va_list args;
	va_start(args, text);

	vprintf(text, args);
	printf("\n");

	va_end(args);
}

void LogHexArray(unsigned char* array, unsigned int arrayLength, char* text, ...)
{
	char textWithVariables[80];
	int sizeMultiplier = 3;

	va_list args;
	va_start(args, text);
	vsnprintf(textWithVariables, sizeof(textWithVariables), text, args);
	va_end(args);

	int textLength = strlen(textWithVariables);
	char tempArray[arrayLength*sizeMultiplier+1+textLength];

	sprintf(tempArray, "%s", textWithVariables);
	for (int i = 0, j = textLength; i < arrayLength; i++, j+=sizeMultiplier)
		if (sizeMultiplier == 3)
			sprintf(&tempArray[j], "%02X ", (unsigned char)array[i]);		//prints like: C4 82 9E FF 33 66 1A EF CD 94 96 2A 9A 74 1D 90 
		else if (sizeMultiplier == 6)
		 	sprintf(&tempArray[j], "0x%02x, ", (unsigned char)array[i]);	//prints like: 0x96, 0x60, 0x82, 0x81, 0x56, 0x8a, 0xc3, 0xe0, 
	Log("%s", tempArray);
}

void Error(int errorType, char* text)
{
	Log(text);

	if (errorType == NETWORK_FATAL)
	{
		pthread_cancel(interceptionThread_Client);
		pthread_cancel(interceptionThread_Server);
		close(clientSocket_Auth);
		close(clientSocket_Game);
		close(serverSocket);
	}
}

//Returns socket for accept(socket);
int ListenForClient(unsigned short port)
{
	int listenSocket;
	struct sockaddr_in botToClientSocketAddr;
	memset(&botToClientSocketAddr, 0, sizeof(botToClientSocketAddr));
	botToClientSocketAddr.sin_family = AF_INET;
	botToClientSocketAddr.sin_addr.s_addr = htonl(INADDR_ANY);
	botToClientSocketAddr.sin_port = htons(port);

	listenSocket = socket(AF_INET, SOCK_STREAM, 0);
	if (listenSocket == -1)
	{
		Log("Failed to create listen socket");
		return -1;
	}

	if (bind(listenSocket, &botToClientSocketAddr, sizeof(botToClientSocketAddr)) == -1)
	{
		Log("Failed to bind");
		return -1;
	}

	if (listen(listenSocket, 1) == -1)
	{
		Log("Failed to listen");
		return -1;
	}

	return listenSocket;
}

//Returns socket
int AcceptClient(int listenSocket)
{
	int clientSocket;
	struct sockaddr_in clientAddr;
	socklen_t clientAddrSize = sizeof(clientAddr);

	clientSocket = accept(listenSocket, &clientAddr, &clientAddrSize);
	if (clientSocket == -1)
		Log("Failed to accept");

	return clientSocket;
}

int ConnectToServer(char* serverIP, unsigned short serverPort)
{
	struct sockaddr_in botToServerSocketAddr;
	memset(&botToServerSocketAddr, 0, sizeof(botToServerSocketAddr));
	botToServerSocketAddr.sin_family = AF_INET;
	botToServerSocketAddr.sin_port = htons(serverPort);
	if (!inet_aton(serverIP, &botToServerSocketAddr.sin_addr))
	{
		Log("Server IP Address invalid");
		return -1;
	}

	serverSocket = socket(AF_INET, SOCK_STREAM, 0);
	if (serverSocket == -1)
	{
		Log("Failed to create socket");
		return -1;
	}

	if (connect(serverSocket, &botToServerSocketAddr, sizeof(botToServerSocketAddr)) == -1)
	{
		Log("Failed to connect()");
		return -1;
	}

	return 0;
}

int ReceivePacket(int sock, void* buffer)
{
	int packetLength;
	int received;
	unsigned int receivedTotal;

	//Get first 2 bytes (packet length), handle partial packets and 2-byte packets
	do
	{
		receivedTotal = 0;
		packetLength = 2;
		while (receivedTotal < packetLength)
		{
			received = recv(sock, &buffer[receivedTotal], packetLength - receivedTotal, 0);
			if (received < 1)
			{
				Log("Recv failed");
				if (received == 0)
					Log("Server/client closed the connection");
				return -1;
			}
			receivedTotal += received;
		}
		packetLength = *(unsigned short*)buffer;
	} while (packetLength <= 2);

	//Get rest of packet, handle partial packets
	while (receivedTotal < packetLength)
	{
		received = recv(sock, &buffer[receivedTotal], packetLength - receivedTotal, 0);
		if (received < 1)
		{
			Log("Recv failed");
			if (received == 0)
				Log("Server/client closed the connection");
			return -1;
		}
		receivedTotal += received;
	}
	return packetLength;
}

int SendToSocket(int sock, unsigned char* packet, unsigned short packetLength)
{
	int sentTotal = 0;
	int sent = 0;

	while (sentTotal < packetLength)
	{
		sent = send(sock, &packet[sentTotal], packetLength - sentTotal, 0);
		if (sent == -1)
			return -1;
		sentTotal += sent;
	}

	return 0;
}

/* Init Packet
BA 00 												//packet length
00 													//packet type
83 A1 7B 7A 										//session key
21 C6 00 00 										//?
26 88 F4 84 EB 86 C1 62 44 2D 2B D3 5D 71 B5 A1 	//rsa key start...
AC 00 9B 55 0F BE DB EC 44 5C 7E BB 26 1F F1 AA 
C7 2D C0 BD CF 8D 11 7D 28 82 D1 D5 1E B3 7B CE 
96 6D 7C C4 F9 46 DB E6 FB ED F3 FD C7 78 23 5F 
CF DA DC D9 D1 D7 46 0E DE 02 90 B2 5C B1 06 D1 
21 9B 3D 2A FF 6E AF 94 AA 94 9C 9A B8 6C 8C 25 
29 43 0F 4F 7A 5F EF 78 6E 15 8B 81 43 F5 2A 59 
19 F4 CD C9 09 53 43 B2 37 DE E7 36 03 05 5C B8 	//rsa key end
4E 95 DD 29 FC 9C C3 77 20 B6 AD 97 F7 E0 BD 07 	//?
2B 60 42 75 7C A2 B1 EA 54 0E 6B 9F 67 E5 66 5D 	//new blowfish key
00 1F 41 68 37 11 56 								//?
D9 BC EB 56 										//xor key
93 64 BE 0F 										//?
*/
void Server_Init_CT2_6(unsigned char* packet, unsigned short packetLength)
{
	unsigned int temp;
	
	//Decrypt XOR
	unsigned int xorKey = *(unsigned int*)(packet + packetLength - 8);
	for (int i = packetLength - 12; i >= 4; i -= 4)
	{
		*(unsigned int*)(packet + i) ^= xorKey;
		xorKey -= *(unsigned int*)(packet + i);
	}

	//Get session key
	SessionKey_Init = *(int*)(packet + 3);

	//Get RSA key, used for sending username/password
	memcpy(rsaKey, packet+11, 128);
	//Another XOR, protecting only the RSA key:
	// 1) xor second 0x40 bytes with first 0x40 bytes
	for (int i = 0; i < 0x40; i+=4)
		*(unsigned int*)(rsaKey+0x40+i) ^= *(unsigned int*)(rsaKey+i);
	// 2) xor bytes 0x0d-0x10 with bytes 0x34-0x38
	*(unsigned int*)(rsaKey+0x0d) ^= *(unsigned int*)(rsaKey+0x34);
	// 3) xor first 0x40 bytes with second 0x40 bytes
	for (int i = 0; i < 0x40; i+=4)
		*(unsigned int*)(rsaKey+i) ^= *(unsigned int*)(rsaKey+0x40+i);
	// 4) swap bytes 0x4d-0x50 with bytes 0x00-0x04
	temp = *(unsigned int*)(rsaKey);
	*(unsigned int*)(rsaKey) = *(unsigned int*)(rsaKey+0x4d);
	*(unsigned int*)(rsaKey+0x4d) = temp;

	//New blowfish key
	Blowfish_Initialize(packet + 155);
}

void Server_Init(unsigned char* packet, unsigned short packetLength)
{
	switch (GameVersion)
	{
		case CT2_6_HighFive:
			Server_Init_CT2_6(packet, packetLength);
			break;
		default:
			Server_Init_CT2_6(packet, packetLength);
	}
}

/* ServerList packet
2A 00 
04 							//packet type
01 							//number of servers
01 							//?
01 							//server #
7F 00 00 01 				//ip
61 1E 00 00 				//port
00 							//age limit (used in korean version)
01 							//pvp flag
00 00 						//current players ?
F4 01 						//max players ?
01 							//server status (down 0x00, up 0x01)
01 00 00 00 				//server type flag (1: Normal, 2: Relax, 4: Public Test, 8: No Label, 16: Character Creation Restricted, 32: Event, 64: Free)
00 							//?
00 00 01 01 01 00 70 B0 91 AF ED AD 7E B0 9C 1D 	//?
*/
void Server_ServerList_CT2_6(unsigned char* packet, unsigned short packetLength)
{
	//todo: support for multiple servers. Currently selecting the first server.

	if (BotType == Interception)
	{
		//change gameserver IP/port before sending to the client
		struct in_addr ip;
		if (!inet_aton(gameServerIPForVM, &ip))
			Error(NETWORK_FATAL, "Invalid IP address for gameServerIPForVM");
		else
			*(unsigned int*)(packet+6) = ip.s_addr;
		*(unsigned int*)(packet+10) = clientToBotGamePort;
	}
}

void Server_ServerList(unsigned char* packet, unsigned short packetLength)
{
	switch (GameVersion)
	{
		case CT2_6_HighFive:
			Server_ServerList_CT2_6(packet, packetLength);
			break;
		default:
			Server_ServerList_CT2_6(packet, packetLength);
	}
}

/* RequestGGAuth Packet
2A 00														//packet length
07 															//packet type
38 0B BC 75 												//session key
23 92 90 4D 18 30 B5 7C 96 61 41 47 05 07 96 FB 00 00 00 	//gameguard magic[19], changes based on game version
FF 90 CF 4E 												//checksum
00 00 00 00 00 00 00 00 00 00 00 00 						//padding
*/
void Client_RequestGGAuth_CT2_6()
{
	unsigned char packet[42];
	unsigned char gameguardAuth_magic_CT2_6[19] = {0x23, 0x01, 0x00, 0x00, 0x67, 0x45, 0x00, 0x00, 0xAB, 0x89, 0x00, 0x00, 0xEF, 0xCD, 0x00, 0x00, 0x00, 0x00, 0x00};

	*(unsigned short*)packet = sizeof(packet);
	packet[2] = 0x07;
	*(unsigned int*)(packet+3) = SessionKey_Init;
	memcpy(packet+7, gameguardAuth_magic_CT2_6, 19);
	*(unsigned int*)(packet+26) = Checksum(packet, 2, 24);
	memset(packet+30, 0, 12);
	Blowfish_Encipher(packet+2, sizeof(packet)-2);
	SendToSocket(serverSocket, packet, sizeof(packet));
}
void Client_RequestGGAuth()
{
	switch (GameVersion)
	{
		case CT2_6_HighFive:
			Client_RequestGGAuth_CT2_6();
			break;
		default:
			Client_RequestGGAuth_CT2_6();
	}
}

/* RequestAuthLogin Packet
	pre-RSA
B2 00 															//packet length
00 																//packet type
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 	//nothing
24 																//unknown
00 00 															//nothing
75 73 65 72 6E 61 6D 65 00 00 00 00 00 00 						//username (not sure if null-terminated, padded, etc)
70 61 73 73 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 	//pass (not sure if null-terminated, padded, etc)
00 00 00 00 													//session key goes here
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 				//gameguard query goes here
08 																//unknown
00 00 00 00 00 00 00 00 00 00									//nothing
00 00 00 00 													//checksum goes here
00 00 00 00 00 00 00 00 00 00 00 00  							//padding
*/
/* 	post-RSA, post-checksum, pre-blowfish
B2 00 															//packet length
00 																//packet type
8E 9C D4 19 3F 1F 80 4B 5D 1A 79 78 F9 EC FD EB 86 1A 71 FD 83 52 58 BD 52 00 54 18 9A 39 08 7A F9 56 DA 7F 30 2C 69 4A 13 EA A2 BE D8 D1 15 D4 3B 2C C3 F7 D8 6B 50 7A 51 D1 E0 90 D6 AE C5 C8 5C 4B 85 F2 9C 3B 2C 0F 4C FF 78 9E 13 36 0A 7E EA AE E3 C3 BB FA 77 43 2D 38 DE 	//nothing
99 																//unknown
B6 FC 															//nothing
8B 0E 92 47 28 B0 7B AA C0 4E 5A 2E 58 28 						//user
02 D5 40 8C E3 40 FE BF 27 05 B0 B4 99 08 D7 B8 DF D6 AD 19 	//pass
F4 3F C5 98 													//session key
23 01 00 00 67 45 00 00 AB 89 00 00 EF CD 00 00 				//gameguard query
08 																//unknown
00 00 00 00 00 00 00 00 00 00 									//nothing
0B 24 E6 0C 													//checksum
00 00 00 00 00 00 00 00 00 00 00 00 							//padding
*/
/* RequestAuthLogin Packet, CT2.6 HighFive Client (though the title screen says Freya), post-RSA, post-checksum, pre-blowfish
C2 00 
00 																						//packet type
76 22 52 E4 FB 93 B0 69 42 38 80 03 4A 18 99 48 F3 4E 44 3C 							//padding start
14 41 C4 97 D5 50 DA 33 B1 C4 E5 A5 63 15 A2 51 B3 84 8C 5E 
26 77 37 E3 FA 4C 47 34 80 AF DC F0 DC 6A EF 78 E7 D1 BF C9 
0E FF D1 FB E7 A6 AF 9C A3 41 36 F7 F3 A2 44 AB 49 49 24 D7 
6C 3C 3F 01 5C 24 46 CB 98 47 88 														//padding end
38 																						//?
4A C9 																					//?
A5 42 79 D8 A7 99 99 F3 1D 86 2A 2B 1C 1F 												//username
98 7F 41 CD 7D FB DA D3 01 72 1D B7 5E 43 02 49 B1 D8 9A 4F 							//password
83 A1 7B 7A 																			//session key
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 										//gameguard query
08 																						//?
00 00 00 00 00 00 DB 37 0B 78 															//?
7E 1F 9E 24 																			//checksum
7D 42 29 AC FE 4D 4B F1 00 00 00 00 CD CE EA 28 00 00 00 00 00 00 00 00 00 00 00 00 	//?
*/
void Client_RequestAuthLogin_CT2_6()
{
	unsigned char packet[178];
	unsigned char ggqueryreply[16] = {0x23, 0x01, 0x00, 0x00, 0x67, 0x45, 0x00, 0x00, 0xAB, 0x89, 0x00, 0x00, 0xEF, 0xCD, 0x00, 0x00}; //default: reply to blank gameguard query

	memset(packet, 0, sizeof(packet));
	*(unsigned short*)packet = sizeof(packet);
	//packet type is (already) 0
	packet[94] = 0x24; //unknown
	memcpy(packet+97,username, sizeof(username));
	memcpy(packet+111,password, sizeof(password));
	RSA_Encrypt(packet+3, rsaKey, 65537); //todo: implement own version of bignum to remove dependency on gmp library

	*(unsigned int*)(packet+131) = SessionKey_Init;

	//gameguard query... clients with GG removed send 0x00's, clients with GG use GGAuth packet values to send a queryreply. sending a known reply for now.
	memcpy(packet+135, ggqueryreply, 16);
	packet[151] = 0x08; //unknown

	*(unsigned int*)(packet+162) = Checksum(packet, 2, 160);
	Blowfish_Encipher(packet+2, sizeof(packet)-2);
	SendToSocket(serverSocket, packet, sizeof(packet));
}
void Client_RequestAuthLogin()
{
	switch (GameVersion)
	{
		case CT2_6_HighFive:
			Client_RequestAuthLogin_CT2_6();
			break;
		default:
			Client_RequestAuthLogin_CT2_6();
	}
}

/*	LoginOK Packet
3A 00 
03 
FE 50 C2 F8 10 59 19 37 		//session key
00 00 00 00 00 00 00 00 EA 03 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 56 67 C8 CC 52 6D 13
*/
void Server_LoginOK_CT2_6(unsigned char* packet, unsigned short packetLength)
{
	SessionKey_LoginOK = *(unsigned long long*)(packet+3);
}

void Server_LoginOK(unsigned char* packet, unsigned short packetLength)
{
	switch (GameVersion)
	{
		case CT2_6_HighFive:
			Server_LoginOK_CT2_6(packet, packetLength);
			break;
		default:
			Server_LoginOK_CT2_6(packet, packetLength);
	}
}

/* RequestServerList packet
22 00 
05 										//packet type
FE 50 C2 F8 10 59 19 37 				//sessionkey (from loginok)
05 										//?
00 00 00 00 00 00 						//padding
CA EB 09 DB 							//checksum
00 00 00 00 00 00 00 00 00 00 00 00 	//padding
*/
void Client_RequestServerList_CT2_6()
{
	unsigned char packet[34];

	*(unsigned short*)packet = sizeof(packet);
	packet[2] = 0x05;
	*(unsigned long long*)(packet+3) = SessionKey_LoginOK;
	packet[11] = 0x04;								//unknown

	memset(packet+12, 0, sizeof(packet)-12);						//padding
	*(unsigned int*)(packet+18) = Checksum(packet, 2, 16);
	Blowfish_Encipher(packet+2, sizeof(packet)-2);
	SendToSocket(serverSocket, packet, sizeof(packet));
}

void Client_RequestServerList()
{
	switch (GameVersion)
	{
		case CT2_6_HighFive:
			Client_RequestServerList_CT2_6();
			break;
		default:
			Client_RequestServerList_CT2_6();
	}
}

/* RequestServerLogin packet
22 00 
02 										//packet type
FE 50 C2 F8 10 59 19 37 				//sessionkey (loginok)
01 										//desired server #
00 00 00 00 00 00 						//padding
CD EF 09 DB 							//checksum
00 00 00 00 00 00 00 00 00 00 00 00		//padding
*/
void Client_RequestServerLogin_CT2_6()
{
	unsigned char packet[34];

	*(unsigned short*)packet = sizeof(packet);
	packet[2] = 0x02;
	*(unsigned long long*)(packet+3) = SessionKey_LoginOK;
	packet[11] = 0x01;								//todo: server selection. currently just selecting server #1.

	memset(packet+12, 0, sizeof(packet)-12);						//padding
	*(unsigned int*)(packet+18) = Checksum(packet, 2, 16);
	Blowfish_Encipher(packet+2, sizeof(packet)-2);
	SendToSocket(serverSocket, packet, sizeof(packet));
}

void Client_RequestServerLogin()
{
	switch (GameVersion)
	{
		case CT2_6_HighFive:
			Client_RequestServerLogin_CT2_6();
			break;
		default:
			Client_RequestServerLogin_CT2_6();
	}
}

/* PlayOK Packet
12 00 
07 								//packet type
8C 87 BD FE 80 1A 47 DB 		//sessionkey playok
06 8A 15 22 0A 17 EF 			//?
*/
void Server_PlayOK_CT2_6(unsigned char* packet, unsigned short packetLength)
{
	SessionKey_PlayOK = *(unsigned long long*)(packet+3);
}

void Server_PlayOK(unsigned char* packet, unsigned short packetLength)
{
	switch (GameVersion)
	{
		case CT2_6_HighFive:
			Server_PlayOK_CT2_6(packet, packetLength);
			break;
		default:
			Server_PlayOK_CT2_6(packet, packetLength);
	}
}

/* ProtocolVersion packet
0B 01 
0E 						//packet type
11 01 00 00 			//protocol
09 07 54 56 03 09 0B 01 07 02 54 54 56 07 00 02 //magic
55 56 00 51 00 53 57 04 07 55 08 54 01 07 01 53 
00 56 55 56 01 06 05 04 51 03 08 51 08 51 56 04 
54 06 55 08 02 09 51 56 01 53 06 55 04 53 00 56 
56 53 01 09 02 09 01 51 54 51 09 55 56 09 03 04 
07 05 55 04 06 55 04 06 09 04 51 01 08 08 06 05 
52 06 04 01 07 54 03 06 52 55 06 55 55 51 01 02 
04 54 03 55 54 01 57 51 55 05 52 05 54 07 51 51 
55 07 02 53 53 00 52 05 52 07 01 54 00 03 05 05 
08 06 05 05 06 03 00 0D 08 01 07 09 03 51 03 07 
53 09 51 06 07 54 0A 50 56 02 52 04 05 55 51 02 
53 00 08 54 04 52 56 06 02 09 00 08 03 53 56 01 
05 00 55 06 08 56 04 0D 06 07 52 06 07 04 0A 06 
01 04 54 04 00 05 02 04 54 00 09 52 53 05 04 01 
04 05 05 01 52 51 52 0D 06 51 08 09 54 53 00 0D 
01 02 03 54 53 01 05 03 08 56 54 07 02 54 0B 06 //end magic
A6 23 F4 FE 		//magic 2
*/
void Client_ProtocolVersion_CT2_6(int protocol)
{
	//todo: allow changing protocols
	unsigned char protocol_magic[] = {0x09, 0x07, 0x54, 0x56, 0x03, 0x09, 0x0B, 0x01, 0x07, 0x02, 0x54, 0x54, 0x56, 0x07, 
	0x00, 0x02, 0x55, 0x56, 0x00, 0x51, 0x00, 0x53, 0x57, 0x04, 0x07, 0x55, 0x08, 0x54, 0x01, 0x07, 0x01, 0x53, 0x00, 0x56, 
	0x55, 0x56, 0x01, 0x06, 0x05, 0x04, 0x51, 0x03, 0x08, 0x51, 0x08, 0x51, 0x56, 0x04, 0x54, 0x06, 0x55, 0x08, 0x02, 0x09, 
	0x51, 0x56, 0x01, 0x53, 0x06, 0x55, 0x04, 0x53, 0x00, 0x56, 0x56, 0x53, 0x01, 0x09, 0x02, 0x09, 0x01, 0x51, 0x54, 0x51, 
	0x09, 0x55, 0x56, 0x09, 0x03, 0x04, 0x07, 0x05, 0x55, 0x04, 0x06, 0x55, 0x04, 0x06, 0x09, 0x04, 0x51, 0x01, 0x08, 0x08, 
	0x06, 0x05, 0x52, 0x06, 0x04, 0x01, 0x07, 0x54, 0x03, 0x06, 0x52, 0x55, 0x06, 0x55, 0x55, 0x51, 0x01, 0x02, 0x04, 0x54, 
	0x03, 0x55, 0x54, 0x01, 0x57, 0x51, 0x55, 0x05, 0x52, 0x05, 0x54, 0x07, 0x51, 0x51, 0x55, 0x07, 0x02, 0x53, 0x53, 0x00, 
	0x52, 0x05, 0x52, 0x07, 0x01, 0x54, 0x00, 0x03, 0x05, 0x05, 0x08, 0x06, 0x05, 0x05, 0x06, 0x03, 0x00, 0x0D, 0x08, 0x01, 
	0x07, 0x09, 0x03, 0x51, 0x03, 0x07, 0x53, 0x09, 0x51, 0x06, 0x07, 0x54, 0x0A, 0x50, 0x56, 0x02, 0x52, 0x04, 0x05, 0x55, 
	0x51, 0x02, 0x53, 0x00, 0x08, 0x54, 0x04, 0x52, 0x56, 0x06, 0x02, 0x09, 0x00, 0x08, 0x03, 0x53, 0x56, 0x01, 0x05, 0x00, 
	0x55, 0x06, 0x08, 0x56, 0x04, 0x0D, 0x06, 0x07, 0x52, 0x06, 0x07, 0x04, 0x0A, 0x06, 0x01, 0x04, 0x54, 0x04, 0x00, 0x05, 
	0x02, 0x04, 0x54, 0x00, 0x09, 0x52, 0x53, 0x05, 0x04, 0x01, 0x04, 0x05, 0x05, 0x01, 0x52, 0x51, 0x52, 0x0D, 0x06, 0x51, 
	0x08, 0x09, 0x54, 0x53, 0x00, 0x0D, 0x01, 0x02, 0x03, 0x54, 0x53, 0x01, 0x05, 0x03, 0x08, 0x56, 0x54, 0x07, 0x02, 0x54, 0x0B, 0x06};
	unsigned char protocol_magic_2[4] = {0xA6, 0x23, 0xF4, 0xFE}; //protocol_ct2_4_to_ct3_0

	unsigned char packet[267];
	*(unsigned short*)packet = sizeof(packet);
	packet[2] = 0x0E;
	*(unsigned int*)(packet+3) = protocol;
	memcpy(packet+7, protocol_magic, sizeof(protocol_magic));
	memcpy(packet+7+sizeof(protocol_magic), protocol_magic_2, sizeof(protocol_magic_2));

	//no blowfish/checksum/padding/etc for this packet...
	SendToSocket(serverSocket, packet, sizeof(packet));
}

void Client_ProtocolVersion(int protocol)
{
	switch (GameVersion)
	{
		case CT2_6_HighFive:
			Client_ProtocolVersion_CT2_6(protocol);
			break;
		default:
			Client_ProtocolVersion_CT2_6(protocol);
	}
}

enum ServerPacket_AuthLogin
{
	INIT = 0x00,
	LOGINFAIL = 0x01,
	ACCOUNTKICKED = 0x02,
	LOGINOK = 0x03,
	SERVERLIST = 0x04,
	PLAYFAIL = 0x06,
	PLAYOK = 0x07,
	GGAUTH = 0x0B
};
int HandleServerPacket_AuthLogin(unsigned char* packet, unsigned short packetLength)
{
	enum ServerPacket_AuthLogin packetType;

	packetType = packet[2];
	switch (packetType)
	{
		case ACCOUNTKICKED:
			Error(NETWORK_FATAL, "AccountKicked packet received");
			break;
		case LOGINFAIL:
			Error(NETWORK_FATAL, "LoginFail packet received");
			break;
		case PLAYFAIL:
			Error(NETWORK_FATAL, "PlayFail packet received");
			break;
		case INIT:
			Log("INIT packet received");
			Server_Init(packet, packetLength);
			if (BotType == Emulation)
				Client_RequestGGAuth();
			break;
		case GGAUTH:	//22 00 0B 83 A1 7B 7A 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 B7 1B BF 1B 8E C3 6A 6A BA 79 AE 
			Log("GGAuth packet received");
			if (BotType == Emulation)
				Client_RequestAuthLogin();
			break;
		case LOGINOK:
			Log("LoginOK packet received"); 
			if (BotType == Emulation)
			{
				Server_LoginOK(packet, packetLength);
				Client_RequestServerList();
			}
			break;
		case SERVERLIST:
			Log("SERVERLIST packet received");
			Server_ServerList(packet, packetLength);
			if (BotType == Emulation)
				Client_RequestServerLogin();
			break;
		case PLAYOK:
			Log("PLAYOK packet received");
			if (BotType == Emulation)
				Server_PlayOK(packet, packetLength);
			LoginState = LOGIN_GAME;
			Log("Disconnecting from AuthServer");
			close(serverSocket);
			Log("Connecting to GameServer");
			if (!ConnectToServer(gameServerIP, gameServerPort))
			{
				Log("Connected to GameServer");
				if (BotType == Interception)
				{
					Blowfish_Encipher(packet+2, packetLength-2);
					SendToSocket(clientSocket_Auth, packet, packetLength);
				}
				else if (BotType == Emulation)
					Client_ProtocolVersion(273);		//todo: allow changing protocol in settings/etc
				return 1;
			}
			else
				Error(NETWORK_FATAL, "Failed to connect to gameserver.");
			break;
		default:
			Log("Server->Bot: No packet handler for this packet type (0x%02x)\n", packetType);
	}

	return 0;
}

void WriteString_CharToUTF16(char* value, unsigned char* packet, int* indexVariable)
{
	for (int i = 0; i <= strlen(value); i++, *indexVariable+=2)	//intentionally reading the null byte at the end of source string, terminating UTF16 string with 3x null bytes
		*((uint16_t*)(packet+*indexVariable)) = value[i];
}

/* RequestPlayerList packet
35 00 
2B 															//packet type
75 00 73 00 65 00 72 00 6E 00 61 00 6D 00 65 00 00 00 		//username in null-terminated UTF16 (can be longer/shorter)
09 B8 69 51 9F A4 DB 2C 									//SessionKey_PlayOK		--strangely, this is bytes [4],[5],[6],[7], then [0],[1],[2],[3]
ED 09 F2 76 94 BC 93 A1 									//SessionKey_LoginOK	-- bytes [0][1][2][3][4][5][6][7]
01 00 00 00 												//?
67 01 00 00 00 00 00 00 00 00 00 00 						//?
*/
void Client_RequestPlayerList_CT2_6()
{
	unsigned char moreMagicValues[8] = {0x67, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

	unsigned char packet[0x80];	//todo: confirm this buffer size is appropriate
	//packet length set later
	packet[2] = 0x2B;
	int index = 3;
	WriteString_CharToUTF16(username, packet, &index);						//username in null-terminated UTF16 (can be longer/shorter)
	//todo: better way of handing packets with variable sizes (changing all the +'s for other versions could get out of hand)
	*(unsigned int*)(packet+index) = SessionKey_PlayOK >> 32;				//SessionKey_PlayOK	bytes [4],[5],[6],[7]
	*(unsigned int*)(packet+index+4) = *(unsigned int*)&SessionKey_PlayOK;	//SessionKey_PlayOK	bytes [0],[1],[2],[3]
	*(unsigned long long*)(packet+index+8) = SessionKey_LoginOK;
	*(unsigned int*)(packet+index+16) = 1;
	memcpy(packet+index+20, moreMagicValues, sizeof(moreMagicValues));

	//set packet length, encrypt, send
	*(unsigned short*)packet = index+20+sizeof(moreMagicValues);
	GamePacket_Encrypt(packet, index+20+sizeof(moreMagicValues), gameKey_Encryption_Server);
	SendToSocket(serverSocket, packet, index+20+sizeof(moreMagicValues));
}

void Client_RequestPlayerList()
{
	switch (GameVersion)
	{
		case CT2_6_HighFive:
			Client_RequestPlayerList_CT2_6();
			break;
		default:
			Client_RequestPlayerList_CT2_6();
	}
}

/* VersionCheck Packet -- unencrypted packet
19 00 					//packet length
2E 						//packet type
01 						//?
B5 CF 18 DE E8 09 B4 DB	//game key, dynamic part
01 00 00 00 			//?
01 00 00 00 			//server id -- not relevant?
01 						//?
00 00 00 00 			//obfuscation key
*/ 
void Server_VersionCheck_CT2_6(unsigned char* packet, unsigned short packetLength)
{
	//todo: handle obfuscation key stuff

	//set up encryption
	unsigned char gameKey_staticPart[8] = {0xC8, 0x27, 0x93, 0x01, 0xA1, 0x6C, 0x31, 0x97};
	memcpy(gameKey_Encryption_Server, packet+4, 8);
	memcpy(gameKey_Encryption_Server+8, gameKey_staticPart, 8);
	memcpy(gameKey_Encryption_Client, packet+4, 8);
	memcpy(gameKey_Encryption_Client+8, gameKey_staticPart, 8);
	memcpy(gameKey_Decryption_Server, packet+4, 8);
	memcpy(gameKey_Decryption_Server+8, gameKey_staticPart, 8);
	memcpy(gameKey_Decryption_Client, packet+4, 8);
	memcpy(gameKey_Decryption_Client+8, gameKey_staticPart, 8);

	if (BotType == Emulation)
		Client_RequestPlayerList();
}

/* CharacterSelect packet
15 00 
12 											//packet type
02 00 00 00 								//character to select (starting at 0)
00 00 00 00 00 00 00 00 00 00 00 00 00 00 	//padding
*/
void Client_CharacterSelect_CT2_6()
{
	//todo: character selecting. just choosing the first character for now.

	unsigned char packet[21] = {0x15, 0x00, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

	GamePacket_Encrypt(packet, sizeof(packet), gameKey_Encryption_Server);
	SendToSocket(serverSocket, packet, sizeof(packet));
}

void Client_CharacterSelect()
{
	switch (GameVersion)
	{
		case CT2_6_HighFive:
			Client_CharacterSelect_CT2_6();
			break;
		default:
			Client_CharacterSelect_CT2_6();
	}
}

/* CharacterSelectionInfo packet
-- 3 chars:
47 04 
09 					//packet type
03 00 00 00 		//char count
07 00 00 00 		//?
00 					//?
41 00 63 00 63 00 6F 00 75 00 6E 00 74 00 32 00 43 00 68 00 61 00 72 00 31 00 00 00 	//character name in null-terminated UTF16 (can be longer/shorter)
97 4B 01 10 		//char id
75 00 73 00 65 00 72 00 6E 00 61 00 6D 00 65 00 32 00 00 00 							//login username in null-terminated UTF16 (can be longer/shorter)
07 C4 D7 1D 		//session id
00 00 00 00 		//clan id
00 00 00 00 		//?
01 00 00 00 		//sex (1 = female)
01 00 00 00 		//race (1 = elf)
19 00 00 00 		//class (0x12 = elf fighter, 0x19 = elf mystic)
01 00 00 00 		//active
06 B3 00 00 		//x
14 A1 00 00 		//y
4B F2 FF FF 		//z
00 00 00 00 00 00 58 40 	//hp (double)
00 00 00 00 00 00 56 40 	//mp (double)
00 00 00 00 00 00 00 00 	//xp (uint64)
00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 06 00 00 00 00 00 00 00 00 00 00 00 A9 01 00 00 CD 01 00 00 00 00 00 00 00 00 00 00 06 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 58 40 00 00 00 00 00 00 56 40 00 00 00 00 19 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 20 4E 00 00 		//unknown[245]
41 00 63 00 63 00 6F 00 75 00 6E 00 74 00 32 00 43 00 68 00 61 00 72 00 32 00 00 00 	//character name in null-terminated UTF16 (can be longer/shorter)
BF 4B 01 10 		//char id
75 00 73 00 65 00 72 00 6E 00 61 00 6D 00 65 00 32 00 00 00 							//login username in null-terminated UTF16 (can be longer/shorter)
07 C4 D7 1D 		//session id
00 00 00 00 		//clan id
00 00 00 00 		//?
01 00 00 00 		//sex
01 00 00 00 		//race
12 00 00 00 		//class
01 00 00 00 		//active
23 B4 00 00 		//x
B5 A0 00 00 		//y
90 F2 FF FF 		//z
00 00 00 00 00 40 5C 40 //hp
00 00 00 00 00 80 43 40 //mp
00 00 00 00 00 00 00 00 //xp
00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 41 09 00 00 00 00 00 00 00 00 00 00 7A 04 00 00 7B 04 00 00 00 00 00 00 00 00 00 00 41 09 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 02 00 00 00 02 00 00 00 02 00 00 00 00 00 00 00 00 40 5C 40 00 00 00 00 00 80 43 40 00 00 00 00 12 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 20 4E 00 00 		//unknown[245]
41 00 63 00 63 00 6F 00 75 00 6E 00 74 00 32 00 43 00 68 00 61 00 72 00 33 00 00 00 	//character name in null-terminated UTF16 (can be longer/shorter)
50 55 01 10 		//char id
75 00 73 00 65 00 72 00 6E 00 61 00 6D 00 65 00 32 00 00 00 							//login username in null-terminated UTF16 (can be longer/shorter)
07 C4 D7 1D 		//session id
00 00 00 00 		//clan id
00 00 00 00 		//?
01 00 00 00 		//sex
00 00 00 00 		//race (0 = human)
0A 00 00 00 		//class (0x0A = human fighter)
01 00 00 00 		//active
DA 9C FE FF 		//x
06 C9 03 00 		//y
0E F2 FF FF 		//z
00 00 00 00 00 80 58 40 //hp
00 00 00 00 00 80 4D 40 //mp
00 00 00 00 00 00 00 00 //xp
00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 06 00 00 00 00 00 00 00 00 00 00 00 A9 01 00 00 CD 01 00 00 00 00 00 00 00 00 00 00 06 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 00 01 00 00 00 01 00 00 00 00 00 00 00 00 80 58 40 00 00 00 00 00 00 56 40 00 00 00 00 0A 00 00 00 01 	//unknown[197]
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 20 4E 00 00  //end part: the same, whether 1/2/3 chars
-- 0 chars:
0C 00 09 00 00 00 00 07 00 00 00 00
*/
void Server_CharacterSelectionInfo_CT2_6(unsigned char* packet, unsigned short packetLength)
{
	//todo: just choosing the first character for now. make it a variable for the user to choose.
	//todo: handle case: 0 characters
	if (BotType == Emulation)
	{
		if (*(unsigned int*)(packet+3) == 0)
		{
			Error(NETWORK_FATAL, "No characters. Crashing for now. Fix me.");
			return;
		}
		Client_CharacterSelect();
	}
}

void Client_GGInit()
{
	//todo: patched clients don't send this, but we should add this for the sake of completion. skipping for now.
}

/* RequestManorList EXPacket
05 00 
D0 
01 00 
*/
void Client_RequestManorList_CT2_6()
{
	unsigned char packet[5] = {0x05, 0x00, 0xD0, 0x01, 0x00};

	GamePacket_Encrypt(packet, sizeof(packet), gameKey_Encryption_Server);
	SendToSocket(serverSocket, packet, sizeof(packet));
}

void Client_RequestManorList()
{
	switch (GameVersion)
	{
		case CT2_6_HighFive:
			Client_RequestManorList_CT2_6();
			break;
		default:
			Client_RequestManorList_CT2_6();
	}
}

/* RequestAllFortressInfo EXPacket
05 00 
D0 
3D 00 
*/
void Client_RequestAllFortressInfo_CT2_6()
{
	unsigned char packet[5] = {0x05, 0x00, 0xD0, 0x3D, 0x00};
	GamePacket_Encrypt(packet, sizeof(packet), gameKey_Encryption_Server);
	SendToSocket(serverSocket, packet, sizeof(packet));
}

void Client_RequestAllFortressInfo()
{
	switch (GameVersion)
	{
		case CT2_6_HighFive:
			Client_RequestAllFortressInfo_CT2_6();
			break;
		default:
			Client_RequestAllFortressInfo_CT2_6();
	}
}

/* RequestKeyMapping EXPacket
05 00 
D0 
21 00 
*/
void Client_RequestKeyMapping_CT2_6()
{
	unsigned char packet[5] = {0x05, 0x00, 0xD0, 0x21, 0x00};
	GamePacket_Encrypt(packet, sizeof(packet), gameKey_Encryption_Server);
	SendToSocket(serverSocket, packet, sizeof(packet));
}

void Client_RequestKeyMapping()
{
	switch (GameVersion)
	{
		case CT2_6_HighFive:
			Client_RequestKeyMapping_CT2_6();
			break;
		default:
			Client_RequestKeyMapping_CT2_6();
	}
}

/* EnterWorld packet
6B 00 
11 
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 //gameguard
C9 BC F2 A7 66 5A 0B 98 36 A5 BD 89 ED 7F E4 D7 //start of magic[72]
6B 49 E2 9F EF 76 EB CE A3 FA F4 BF 0C 64 A3 B4 
A4 CE DC C6 08 3E 6E EA 45 CA D3 FE 88 13 87 B8 
06 2C 96 F0 9B 1E 8E BC C6 9B 98 C8 63 16 CF D0 
29 00 00 00 C0 A8 9C 82 						//end of magic[72]
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
*/
void Client_EnterWorld_CT2_6()
{
	unsigned char magic[] = { 0xC9, 0xBC, 0xF2, 0xA7, 0x66, 0x5A, 0x0B, 0x98, 0x36, 0xA5, 0xBD, 0x89, 0xED, 0x7F, 0xE4, 0xD7,
							0x6B, 0x49, 0xE2, 0x9F, 0xEF, 0x76, 0xEB, 0xCE, 0xA3, 0xFA, 0xF4, 0xBF, 0x0C, 0x64, 0xA3, 0xB4, 
							0xA4, 0xCE, 0xDC, 0xC6, 0x08, 0x3E, 0x6E, 0xEA, 0x45, 0xCA, 0xD3, 0xFE, 0x88, 0x13, 0x87, 0xB8, 
							0x06, 0x2C, 0x96, 0xF0, 0x9B, 0x1E, 0x8E, 0xBC, 0xC6, 0x9B, 0x98, 0xC8, 0x63, 0x16, 0xCF, 0xD0, 
							0x29, 0x00, 0x00, 0x00, 0xC0, 0xA8, 0x9C, 0x82 };

	unsigned char packet[107];
	*(unsigned short*)packet = sizeof(packet);
	packet[2] = 0x11;
	memset(packet+3, 0, 16);	//todo: insert gameguard 16 bytes
	memcpy(packet+19, magic, sizeof(magic));
	memset(packet+19+sizeof(magic), 0, 16);

	GamePacket_Encrypt(packet, sizeof(packet), gameKey_Encryption_Server);
	SendToSocket(serverSocket, packet, sizeof(packet));
}

void Client_EnterWorld()
{
	switch (GameVersion)
	{
		case CT2_6_HighFive:
			Client_EnterWorld_CT2_6();
			break;
		default:
			Client_EnterWorld_CT2_6();
	}
}

/* RequestSkillCoolTime packet
03 00 
A6
*/
void Client_RequestSkillCoolTime_CT2_6()
{
	unsigned char packet[3] = { 0x03, 0x00, 0xA6 };

	GamePacket_Encrypt(packet, sizeof(packet), gameKey_Encryption_Server);
	SendToSocket(serverSocket, packet, sizeof(packet));
}

void Client_RequestSkillCoolTime()
{
	switch (GameVersion)
	{
		case CT2_6_HighFive:
			Client_RequestSkillCoolTime_CT2_6();
			break;
		default:
			Client_RequestSkillCoolTime_CT2_6();
	}
}

/* CharSelected packet
EB 00 
0B 
54 00 65 00 73 00 74 00 43 00 68 00 61 00 72 00 4E 00 61 00 6D 00 65 00 00 00 		//character name in null-terminated UTF16 (can be longer/shorter)
F5 C1 01 10 										//id
00 00 53 A9 FF EA 00 00 00 00 00 00 
00 00 01 00 00 00 01 00 00 00 19 00 00 00 01 00 
00 00 85 B8 00 00 44 A1 00 00 4B F2 FF FF 00 00 
00 00 00 00 58 40 00 00 00 00 00 00 56 40 00 00 
00 00 00 00 00 00 00 00 00 00 01 00 00 00 00 00 
00 00 00 00 00 00 25 00 00 00 15 00 00 00 19 00 
00 00 28 00 00 00 18 00 00 00 17 00 00 00 11 02 
00 00 00 00 00 00 19 00 00 00 00 00 00 00 00 00 
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
00 00 00 00 00 00 00 00 00 00 00 00 00 00 
*/
void Server_CharSelected_CT2_6(unsigned char* packet, unsigned short packetLength)
{
	if (BotType == Emulation)
	{
		Client_GGInit();
		Client_RequestManorList();
		Client_RequestAllFortressInfo();
		Client_RequestKeyMapping();
		sleep(1);
		Client_EnterWorld();
		sleep(2);
		Client_RequestSkillCoolTime();
		Client_RequestSkillCoolTime(); //intentionally sending this twice.
	}
}

void Client_NetPingReply_CT2_6(int id)
{
	unsigned char packet[15];
	*(unsigned short*)packet = sizeof(packet);
	packet[2] = 0xB1;
	*(unsigned int*)(packet+3) = id;
	*(unsigned int*)(packet+7) = 10; //todo: supposed to be a random number, from 5-15.
	*(unsigned int*)(packet+11) = 6144;	// if >= ct2.4 then 6144, else 2048

	GamePacket_Encrypt(packet, sizeof(packet), gameKey_Encryption_Server);
	SendToSocket(serverSocket, packet, sizeof(packet));
}

void Client_NetPingReply(int id)
{
	switch (GameVersion)
	{
		case CT2_6_HighFive:
			Client_NetPingReply_CT2_6(id);
			break;
		default:
			Client_NetPingReply_CT2_6(id);
	}
}

void Server_NetPing_CT2_6(unsigned char* packet, unsigned short packetLength)
{
	int id = *(unsigned int*)(packet+3);
	Client_NetPingReply(id);
}

/* GameGuardReply packet
14 00 
CB 
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
*/
void Client_GameGuardReply_CT2_6()
{
	//todo: do this properly. just sending a blank reply for now.
	unsigned char packet[20];
	*(unsigned short*)packet = sizeof(packet);
	packet[2] = 0xCB;

	memset(packet+3, 0, sizeof(packet)-3);

	GamePacket_Encrypt(packet, sizeof(packet), gameKey_Encryption_Server);
	SendToSocket(serverSocket, packet, sizeof(packet));
}

void Client_GameGuardReply()
{
	switch (GameVersion)
	{
		case CT2_6_HighFive:
			Client_GameGuardReply_CT2_6();
			break;
		default:
			Client_GameGuardReply_CT2_6();
	}
}

/* GameGuardQuery packet
13 00 
74 
D9 3D 53 27 1D A5 72 2E 8B 03 17 20 A3 1E 5B C3 
*/
void Server_GameGuardQuery_CT2_6(unsigned char* packet, unsigned short packetLength)
{
	//todo: do this properly. just sending a blank reply for now.
	Client_GameGuardReply();
}

/*
GameServer Packet Handling:
Doing this for performance reasons: avoids having to check game version on every packet handler. This way we check versions once, then populate the jump table.
There are ~50 versions right now, and many packets are different in each version.
*/
typedef void (*Handler)(unsigned char* packet, unsigned short packetLength);
Handler ServerPacket_JumpTable[256];
void Default_Handler(unsigned char* packet, unsigned short packetLength)
{
	Log("Server->Bot: No packet handler for this packet type (0x%02x)\n", packet[2]);
}
void Init_ServerPacketJumpTable()
{
	//set defaults
	for (int i = 0; i < 256; i++)
		ServerPacket_JumpTable[i] = &Default_Handler;

	switch (GameVersion)
	{
		case CT2_6_HighFive:
			ServerPacket_JumpTable[0x09] = &Server_CharacterSelectionInfo_CT2_6;
			ServerPacket_JumpTable[0x0B] = &Server_CharSelected_CT2_6;
			ServerPacket_JumpTable[0x2E] = &Server_VersionCheck_CT2_6;
			ServerPacket_JumpTable[0xD9] = &Server_NetPing_CT2_6;
			ServerPacket_JumpTable[0x74] = &Server_GameGuardQuery_CT2_6;
			break;
		default:
			ServerPacket_JumpTable[0x09] = &Server_CharacterSelectionInfo_CT2_6;
			ServerPacket_JumpTable[0x0B] = &Server_CharSelected_CT2_6;
			ServerPacket_JumpTable[0x2E] = &Server_VersionCheck_CT2_6;
			ServerPacket_JumpTable[0xD9] = &Server_NetPing_CT2_6;
			ServerPacket_JumpTable[0x74] = &Server_GameGuardQuery_CT2_6;
	}
}


void* InterceptionThread_Server(void* unused)
{
	int packetLength;
	unsigned char* packet = receiveBuffer_Server;

	//First packet changes blowfish key, so it needs to be handled differently
	packetLength = ReceivePacket(serverSocket, packet);
	if (packetLength < 3)
	{
		Error(NETWORK_FATAL, "InterceptionThread_Server() <- ReceivePacket() failed");
		return NULL;
	}
	//Need to make a copy of this packet to send to the client later 
	//-- must delay sending to the client until we've set up blowfish with the new key, so that we can decrypt client->server communication properly.
	unsigned char packetCopy[packetLength];
	memcpy(packetCopy, packet, packetLength);
	Blowfish_Initialize(staticBlowfishKey);
	Blowfish_Decipher(packet+2, packetLength-2);
	LogHexArray(packet, packetLength, "Server->Bot: ");
	HandleServerPacket_AuthLogin(packet, packetLength);
	SendToSocket(clientSocket_Auth, packetCopy, packetLength);

	//Auth Loop: Receive packet from server, send to client
	//note: we need to intercept the serverlist packet and change gameserver IP/port before sending to the client
	while(1)
	{
		packetLength = ReceivePacket(serverSocket, packet);
		if (LoginState == LOGIN_GAME)
			break;
		if (packetLength < 3)
		{
			Error(NETWORK_FATAL, "InterceptionThread_Server() <- ReceivePacket() failed");
			return NULL;
		}
		Blowfish_Decipher(packet+2, packetLength-2);
		LogHexArray(packet, packetLength, "Server->Bot: ");
		if (HandleServerPacket_AuthLogin(packet, packetLength))
			break;
		Blowfish_Encipher(packet+2, packetLength-2);
		if(SendToSocket(clientSocket_Auth, packet, packetLength) == -1)
		{
			Error(NETWORK_FATAL, "InterceptionThread_Server() <- SendToSocket() failed");
			return NULL;
		}
	}

	//GameServer now
	Init_ServerPacketJumpTable();

	//one unencrypted packet
	packetLength = ReceivePacket(serverSocket, packet);
	if (packetLength < 3)
	{
		Error(NETWORK_FATAL, "InterceptionThread_Server() <- ReceivePacket() failed");
		return NULL;
	}
	LogHexArray(packet, packetLength, "Server->Bot: ");
	ServerPacket_JumpTable[packet[2]](packet, packetLength);
	SendToSocket(clientSocket_Game, packet, packetLength);

	//Game Loop: Receive packet from server, send to client
	while(1)
	{
		packetLength = ReceivePacket(serverSocket, packet);
		if (packetLength < 3)
		{
			Error(NETWORK_FATAL, "InterceptionThread_Server() <- ReceivePacket() failed");
			return NULL;
		}
		SendToSocket(clientSocket_Game, packet, packetLength);
		GamePacket_Decrypt(packet, packetLength, gameKey_Decryption_Server);
		LogHexArray(packet, packetLength, "Server->Bot: ");
		//ServerPacket_JumpTable[packet[2]](packet, packetLength); //not needed until we start modifying packets
	}

	Error(NETWORK_FATAL, "InterceptionThread_Server thread ended unexpectedly...");
	return NULL;
}

void* InterceptionThread_Client(void* unused)
{
	int listenSocket;
	int packetLength;
	unsigned char* packet = receiveBuffer_Client;

	//Wait for official client to attempt connection to AuthServer
	Log("Waiting for client connection...");
	listenSocket = ListenForClient(clientToBotAuthPort);
	if (listenSocket == -1)
	{
		Error(NETWORK_FATAL, "ListenForClient failed (auth)");
		return NULL;
	}
	clientSocket_Auth = AcceptClient(listenSocket);
	if (clientSocket_Auth == -1)
	{
		Error(NETWORK_FATAL, "AcceptClient failed (auth)");
		return NULL;
	}
	Log("Client connected (auth).");

	//Connect to server
	Log("Connecting to AuthServer");
	if (!ConnectToServer(authServerIP, authServerPort))
	{
		Log("Connected to AuthServer");
		//Start server<->bot network thread
		if (pthread_create(&interceptionThread_Server, NULL, &InterceptionThread_Server, NULL))
		{
			Error(NETWORK_FATAL, "Failed to create server<->bot Interception thread");
			return NULL;
		}
	}
	else
	{
		Error(NETWORK_FATAL, "Failed to connect to authserver.");
		return NULL;
	}

	//Prepare another socket for GameServer 
	//-- This is out of order since the official client attempts connection to GameServer early
	listenSocket = ListenForClient(clientToBotGamePort);
	if (listenSocket == -1)
	{
		Error(NETWORK_FATAL, "ListenForClient failed (game)");
		return NULL;
	}

	//Auth Loop: Receive packet from client, send to server
	while(1)
	{
		packetLength = ReceivePacket(clientSocket_Auth, packet);
		if (LoginState == LOGIN_GAME)
		{
			close(clientSocket_Auth);
			break;
		}
		if (packetLength < 3)
		{
			Error(NETWORK_FATAL, "InterceptionThread_Client() <- ReceivePacket() failed");
			return NULL;
		}
		if(SendToSocket(serverSocket, packet, packetLength) == -1)
		{
			Error(NETWORK_FATAL, "InterceptionThread_Client() <- SendToSocket() failed");
			return NULL;
		}
		Blowfish_Decipher(packet+2, packetLength-2);
		LogHexArray(packet, packetLength, "Client->Bot: ");
	}

	//Finish setting up socket for GameServer
	clientSocket_Game = AcceptClient(listenSocket);
	if (clientSocket_Game == -1)
	{
		Error(NETWORK_FATAL, "AcceptClient failed (game)");
		return NULL;
	}
	Log("Client connected (game).");

	//GameServer now
	//one unencrypted packet (should be ProtocolVersion packet)
	packetLength = ReceivePacket(clientSocket_Game, packet);
	if (packetLength < 3)
	{
		Error(NETWORK_FATAL, "InterceptionThread_Client() <- ReceivePacket() failed");
		return NULL;
	}
	LogHexArray(packet, packetLength, "Client->Bot: ");
	if(SendToSocket(serverSocket, packet, packetLength) == -1)
	{
		Error(NETWORK_FATAL, "InterceptionThread_Client() <- SendToSocket() failed");
		return NULL;
	}

	//Game Loop: Receive packet from client, send to server
	while(1)
	{
		packetLength = ReceivePacket(clientSocket_Game, packet);
		if (packetLength < 3)
		{
			Error(NETWORK_FATAL, "InterceptionThread_Client() <- ReceivePacket() failed");
			return NULL;
		}
		if(SendToSocket(serverSocket, packet, packetLength) == -1)
		{
			Error(NETWORK_FATAL, "InterceptionThread_Client() <- SendToSocket() failed");
			return NULL;
		}
		GamePacket_Decrypt(packet, packetLength, gameKey_Decryption_Client);
		LogHexArray(packet, packetLength, "Client->Bot: ");
	}
	
	Error(NETWORK_FATAL, "InterceptionThread_Client thread ended unexpectedly...");
	return NULL;
}

void* EmulationThread_Server(void* unused)
{
	int listenSocket;
	int packetLength;
	unsigned char* packet = receiveBuffer_Client;

	//Connect to server
	Log("Connecting to AuthServer");
	if (ConnectToServer(authServerIP, authServerPort))
	{
		Error(NETWORK_FATAL, "Failed to connect to authserver.");
		return NULL;
	}
	Log("Connected to AuthServer");

	Blowfish_Initialize(staticBlowfishKey);

	//Auth Loop: Receive packet from server, handle it
	while(1)
	{
		packetLength = ReceivePacket(serverSocket, packet);
		if (LoginState == LOGIN_GAME)
			break;
		if (packetLength < 3)
		{
			Error(NETWORK_FATAL, "EmulationThread_Server() <- ReceivePacket() failed");
			return NULL;
		}
		Blowfish_Decipher(packet+2, packetLength-2);
		LogHexArray(packet, packetLength, "Server->Bot: ");
		if (HandleServerPacket_AuthLogin(packet, packetLength))
			break;
	}

	//Gameserver now
	Init_ServerPacketJumpTable();

	//one unencrypted packet
	packetLength = ReceivePacket(serverSocket, packet);
	if (packetLength < 3)
	{
		Error(NETWORK_FATAL, "EmulationThread_Server() <- ReceivePacket() failed");
		return NULL;
	}
	LogHexArray(packet, packetLength, "Server->Bot: ");
	ServerPacket_JumpTable[packet[2]](packet, packetLength);
	
	//Game Loop: Receive packet from server, handle it
	while(1)
	{
		packetLength = ReceivePacket(serverSocket, packet);
		if (packetLength < 3)
		{
			Error(NETWORK_FATAL, "EmulationThread_Server() <- ReceivePacket() failed");
			return NULL;
		}
		GamePacket_Decrypt(packet, packetLength, gameKey_Decryption_Server);
		LogHexArray(packet, packetLength, "Server->Bot: ");
		ServerPacket_JumpTable[packet[2]](packet, packetLength);
	}

	Error(NETWORK_FATAL, "EmulationThread_Server thread ended unexpectedly...");
	return NULL;
}

int main(int argc, char** argv)
{
	//todo: let user choose options
	BotType = Interception;
	GameVersion = CT2_6_HighFive;
	LoginState = LOGIN_AUTH;

	if (BotType == Interception)
	{
		if (pthread_create(&interceptionThread_Client, NULL, &InterceptionThread_Client, NULL))
			Error(NETWORK_FATAL, "Failed to create main Interception thread");
	}
	else if (BotType == Emulation)
	{
		if (pthread_create(&emulationThread_Server, NULL, &EmulationThread_Server, NULL))
			Error(NETWORK_FATAL, "Failed to create main Emulation thread");
	}

	getchar(); //todo: proper event handler for GUI, or LUA interpreter for terminal
	return 0;
}