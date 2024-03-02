#include <stdio.h>
#include <stdarg.h>
#include <pthread.h>
#include <netinet/in.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "blowfish.h"
#include "xor_crypt.h"

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

	//change gameserver IP/port before sending to the client
	struct in_addr ip;
	if (!inet_aton(gameServerIPForVM, &ip))
		Error(NETWORK_FATAL, "Invalid IP address for gameServerIPForVM");
	else
		*(unsigned int*)(packet+6) = ip.s_addr;
	*(unsigned int*)(packet+10) = clientToBotGamePort;
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
			break;
		case GGAUTH:	//22 00 0B 83 A1 7B 7A 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 B7 1B BF 1B 8E C3 6A 6A BA 79 AE 
			Log("GGAuth packet received");
			break;
		case LOGINOK:
			Log("LoginOK packet received"); 
			break;
		case SERVERLIST:
			Log("SERVERLIST packet received");
			Server_ServerList(packet, packetLength);
			break;
		case PLAYOK:
			Log("PLAYOK packet received");
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
	
}
void Init_ServerPacketJumpTable()
{
	//set defaults
	for (int i = 0; i < 256; i++)
		ServerPacket_JumpTable[i] = &Default_Handler;

	switch (GameVersion)
	{
		case CT2_6_HighFive:
			ServerPacket_JumpTable[0x2E] = &Server_VersionCheck_CT2_6;
			break;
		default:
			ServerPacket_JumpTable[0x2E] = &Server_VersionCheck_CT2_6;
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

	getchar(); //todo: proper event handler for GUI, or LUA interpreter for terminal
	return 0;
}