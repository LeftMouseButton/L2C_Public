#include <stdio.h>
#include <stdarg.h>
#include <pthread.h>
#include <netinet/in.h>
#include <string.h>
#include <arpa/inet.h>

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
pthread_t serverThread;
pthread_t interceptionThread = 0;
unsigned short clientToBotAuthPort = 2106;
int clientSocket_Auth;
int serverSocket;
char authServerIP[] = "127.0.0.1";
unsigned short authServerPort = 2107;


//Wrapper for easy redirect/disable later
void Log(char* text, ...)
{
	va_list args;
	va_start(args, text);

	vprintf(text, args);
	printf("\n");

	va_end(args);
}

void Error(int errorType, char* text)
{
	Log(text);

	if (errorType == NETWORK_FATAL)
	{
		pthread_cancel(interceptionThread);
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

void* ServerThread_Interception(void* unused)
{
	return NULL;
}

void* InterceptionThread(void* unused)
{
	int listenSocket;

	//Wait for official client to attempt connection to auth server
	Log("Waiting for client connection...");
	listenSocket = ListenForClient(clientToBotAuthPort);
	if (listenSocket == -1)
	{
		Error(NETWORK_FATAL, "InterceptionThread() ListenForClient failed (auth)");
		return NULL;
	}
	clientSocket_Auth = AcceptClient(listenSocket);
	if (clientSocket_Auth == -1)
	{
		Error(NETWORK_FATAL, "InterceptionThread() AcceptClient failed (auth)");
		return NULL;
	}
	Log("Client connected (auth).");

	return NULL;
}

int main(int argc, char** argv)
{
	//todo: let user choose options
	BotType = Interception;

	if (BotType == Interception)
	{
		if (pthread_create(&interceptionThread, NULL, &InterceptionThread, NULL))
			Error(NETWORK_FATAL, "Failed to create main Interception thread");
	}

	getchar(); //todo: proper event handler for GUI, or LUA interpreter for terminal
	return 0;
}