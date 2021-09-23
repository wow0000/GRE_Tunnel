#include "GRE.h"

[[noreturn]] void GRE::receiver(HMODULE wintun) {
	InitializeWintun(wintun); // Required due to being initialized in another file and wintun won't provide any .lib

	sockaddr_in SenderAddr{};
	int SenderAddrSize = sizeof(SenderAddr);

	char RecvBuf[8192];
	int BufLen = 8192;
	int rBufLen;
	el::Logger* defaultLogger = el::Loggers::getLogger("default");

	while (true) {
		rBufLen = recvfrom(s,
			RecvBuf, BufLen, 0, (SOCKADDR*)&SenderAddr, &SenderAddrSize);

		if (rBufLen == SOCKET_ERROR)
		{
			LOG(WARNING) << "Socket error: " << WSAGetLastError();
			continue;
		}

		if (SenderAddr.sin_addr.S_un.S_addr != RecvAddr.sin_addr.S_un.S_addr) {
			LOG(INFO) << "Received a packet from an invalid IP";
			continue;
		}
		
		// Prevent IPv6 & Bogus packets
		if (RecvBuf[0] >> 4 != 4)
		{
			continue;
		}

		int iphl = ((RecvBuf[0] & 0x0f) * 32) / 8; // This take the second half of a byte then *32/8 -> length of the ip header
		int totalSize = rBufLen - iphl - GRE_SIZE;
		int startSize = iphl + GRE_SIZE;

		if (iphl > 60) {
			LOG(INFO) << "Received a packet with a invalid IPHL: " << iphl;
			continue;
		}

		// Check for a valid IPv4 GRE Header (No key/sequence support)
		if (memcmp((RecvBuf + iphl), "\0\0\x08\0", GRE_SIZE) != 0) {
			LOG(INFO) << "Received a packet with an invalid GRE Header";
			continue;
		}

		// Check if the contained packet is a IPv4 one
		if ((RecvBuf+startSize)[0] >> 4 != 4)
		{
			continue;
		}

		// Whitelist protocols
		int protocol = (RecvBuf + startSize)[9];
		if (protocol != IPPROTO_TCP && protocol != IPPROTO_ICMP && protocol != IPPROTO_UDP) {
			LOG(INFO) << "Received a packet with an invalid protocol: " << protocol;
			continue;
		}


		BYTE* OutgoingPacket = WintunAllocateSendPacket(Session, totalSize);
		if (!OutgoingPacket)
		{
			DWORD lastError = GetLastError();
			LOG_EVERY_N(5, WARNING) << "Could not allocate enough memory to send packet " << totalSize << " : " << lastError;

			// Looks like we can't receive any more packets so we are going to restart the driver's session
			if (lastError == ERROR_HANDLE_EOF) {
				LOG(WARNING) << "Restarting WinTun session due to an invalid packet.";
				reset_adapter = true;

				WintunEndSession(Session);
				Session = WintunStartSession(Adapter, WINTUN_MAX_RING_CAPACITY / 2);

				if (!Session) {
					WintunFreeAdapter(Adapter);
					LOG(FATAL) << "Could not create session";
				}
				LOG(INFO) << "Successfully restarted WinTun Session.";
				reset_adapter = false;
			}
			continue;
		}
		memcpy(OutgoingPacket, (RecvBuf + startSize), totalSize);
		WintunSendPacket(Session, OutgoingPacket);
	}
}

void GRE::sender(char* packet, unsigned int size) {
	int newSize = size + GRE_SIZE; // GRE size

	if (newSize > SEND_BUFFER)
		LOG(WARNING) << "Sending buffer overflowed: " << newSize << " bytes";

	// To modify the GRE Header (keys, sequences..) it'll need to be done here
	memcpy(sendBuf, "\0\0\x08\0", GRE_SIZE); // GRE size
	memcpy(sendBuf + GRE_SIZE, packet, size);

	sendto(s, sendBuf, newSize, 0, (SOCKADDR*)&RecvAddr, sizeof(RecvAddr));
}
