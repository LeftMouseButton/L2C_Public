A proof-of-concept bot for Lineage 2 (2003~).

Designed with 2 different options in mind:
- Interception: Intercept/Modify packets sent from/to the official game client.
- Emulation: Imitate the official game client.


https://github.com/LeftMouseButton/L2C_Public/assets/144728977/acf5da9d-9b2c-4cd1-a3b2-733bfd61b8e5


https://github.com/LeftMouseButton/L2C_Public/assets/144728977/2b7e25f1-abfe-4427-b51e-9a8e9b2d90d7



Completed:
- Login & Gameplay via Interception
- Login (Auth+GameServer) via Emulation
- Crypt
- - Blowfish
- - XOR
- - RSA
- Platform:
- - Linux

Todo:
- Clean up code structure
- Packets: A few hundred, for each version of the game
- Game Data
- UI, GUI
- Scripting: LUA
- Platform: Windows
- ...






-------

	Auth Server:
		Server sends Init packet immediately after connection
			Enciphered with blowfish (static key)
			Encrypted with an XOR algorithm (the key is generated randomly by the server and placed near the end of the packet)
			Contains a session key
			Contains an RSA key (used for encrypting username/password)
				RSA key is encrypted with another (static) XOR algorithm
			Contains a new blowfish key (replaces static key)
		Client replies with RequestGGAuth
			Session ID
			GameGuard magic values
			XOR Checksum (static)
			Enciphered with blowfish
		Server replies with GGAuth
			Contains GameGuard query (16 bytes starting at packet[7])
			Enciphered with blowfish
		Client replies with RequestAuthLogin
			Username, Password, and an unknown 0x24 value encrypted via server's RSA
			SessionID
			GameGuard query response
			Unknown 0x08 value
			XOR Checksum (static)
			Enciphered with blowfish
		Server replies with LoginOK or LoginFail
		User accepts Terms of Service
		Client sends RequestServerList
		Server replies with ServerList
		User selects a server and clicks confirm
		Client sends RequestServerLogin
		Server replies with PlayOK
			Contains a session key for GameServer
		Client disconnects from auth server and connects to game server

	Now we drop all encryption and start over with unencrypted communication.

	Game Server (login section):
		Client sends ProtocolVersion_AuthLogin packet
			Contains protocol version (int32), change depending on game version
			256 bytes of static values (protocol_magic)
			Another 4 bytes, change depending on game version (protocol_magic_2)
		Server sends VersionCheck_CryptInit packet
			Contains a key for XOR-based encryption (used for encrypting all subsequent packets)
				Encryption key consists of 16 bytes:
					1x int32, sent from server
					1x int32, sent from server
					1x int32, hardcoded, incremented by the amount of bytes processed by each encrypt/decrypt operation
					1x int32, hardcoded
			Contains an obfuscation key (if not 0, client will shuffle its packet opcodes)
		Client sends RequestPlayerList packet
			Contains the session keys from auth PlayOK and auth LoginOK
		...

	Game Server (gameplay section):
		...
