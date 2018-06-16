import std.stdio;

extern (C) uint SteamAPI_ISteamNetworkingSockets_CreateListenSocket(ptrdiff_t instance_ptr, int nsteam_connect_virutal_port, uint nip, ushort nport);
extern (C++) class ISteamNetworkingSockets{}; // NB: DON'T USE THIS it's just a neat name
extern (C) ISteamNetworkingSockets *SteamNetworkingSockets();
extern (C) ISteamNetworkingSockets *SteamNetworkingSocketsGameServer();

void main() {
	writeln(&SteamAPI_ISteamNetworkingSockets_CreateListenSocket);
	ptrdiff_t ptr = cast(ptrdiff_t)SteamNetworkingSockets();
	uint x = SteamAPI_ISteamNetworkingSockets_CreateListenSocket(ptr, 444, 0, 0);
}
