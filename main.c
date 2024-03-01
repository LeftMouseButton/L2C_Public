#include <stdio.h>
#include <stdarg.h>
#include <pthread.h>
#include <netinet/in.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>

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
int clientSocket_Auth = -1;
int serverSocket = -1;
char authServerIP[] = "127.0.0.1";
unsigned short authServerPort = 2107;
unsigned char receiveBuffer_Server[65535]; //recv packets into this buffer
unsigned char receiveBuffer_Client[65535]; //recv packets into this buffer


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
		close(clientSocket_Auth);
		close(serverSocket);
		pthread_cancel(interceptionThread_Client);
		pthread_cancel(interceptionThread_Server);
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

void* InterceptionThread_Server(void* unused)
{
	int packetLength;
	unsigned char* packet = receiveBuffer_Server;

	//Auth Loop: Receive packet from server, send to client
	while(1)
	{
		packetLength = ReceivePacket(serverSocket, packet);
		if (packetLength < 3)
		{
			Error(NETWORK_FATAL, "InterceptionThread_Server() <- ReceivePacket() failed");
			return NULL;
		}
		LogHexArray(packet, packetLength, "Server->Bot: ");
		if(SendToSocket(clientSocket_Auth, packet, packetLength) == -1)
		{
			Error(NETWORK_FATAL, "InterceptionThread_Server() <- SendToSocket() failed");
			return NULL;
		}
	}


	return NULL;
}

void* InterceptionThread_Client(void* unused)
{
	int listenSocket;
	int packetLength;
	unsigned char* packet = receiveBuffer_Client;

	//Wait for official client to attempt connection to auth server
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

	//Auth Loop: Receive packet from client, send to server
	while(1)
	{
		packetLength = ReceivePacket(clientSocket_Auth, packet);
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
	}

	return NULL;
}

int main(int argc, char** argv)
{
	//todo: let user choose options
	BotType = Interception;

	if (BotType == Interception)
	{
		if (pthread_create(&interceptionThread_Client, NULL, &InterceptionThread_Client, NULL))
			Error(NETWORK_FATAL, "Failed to create main Interception thread");
	}

	getchar(); //todo: proper event handler for GUI, or LUA interpreter for terminal
	return 0;
}