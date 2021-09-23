#pragma once
extern bool reset_adapter;
extern WINTUN_SESSION_HANDLE Session;
extern GRE* gre;

// This function handles the packet sent by the client through the virtual network card
[[noreturn]] void wintun_receive_loop() {
	DWORD PacketSize;
	BYTE* Packet;
	HANDLE evnt = WintunGetReadWaitEvent(Session);
	int i = 0;
	while (true) {
		// The packets received here is the full ipv4 frame from the Wintun interface
		if (reset_adapter) {
			std::this_thread::yield();
			if (Session)
				evnt = WintunGetReadWaitEvent(Session);
			continue;
		}
		Packet = WintunReceivePacket(Session, &PacketSize);

		if (!Packet) {
			if (i >= 15)
			{
				i = 0;
				WaitForSingleObject(evnt, 1);
				continue;
			}
			i += 1;
			continue;
		}
		i = 0;
		// The full frame will be encapsulated over GRE to be sent through the tunnel
		gre->sender(reinterpret_cast<char*>(Packet), PacketSize);

		WintunReleaseReceivePacket(Session, Packet);
	}
}

// Will free Wintun adapter before exiting
BOOL WINAPI exit_handler(DWORD dwCtrlType)
{
	WintunFreeAdapter(Adapter);
	std::cout << "Exiting..." << std::endl;
	exit(0);
	return FALSE;
}
