#include "GRE.h"

#define RecvBufSize 32768

[[noreturn]] void GRE::receiver(HMODULE wintun) {
	sockaddr_in SenderAddr{};
	int is_flooding = 0;
	int SenderAddrSize = sizeof(sockaddr_in);
	int rBufLen;
	static char RecvBuf[RecvBufSize];

	if (!wintun || !InitializeWintun(wintun) || !Session) {
		LOG(ERROR) << "Could not load wintun.dll";
		exit(-1);
	}
	el::Logger* defaultLogger = el::Loggers::getLogger("default");

	while (true) {
		rBufLen = recvfrom(s, RecvBuf, RecvBufSize, 0, (SOCKADDR*)&SenderAddr, &SenderAddrSize);
		if (rBufLen == SOCKET_ERROR)
		{
			LOG_IF(!is_flooding, WARNING) << "Socket error: " << WSAGetLastError();
			is_flooding = 1;
			continue;
		}

		if (rBufLen < GRE_SIZE + 20) {
			LOG_IF(!is_flooding, INFO) << "Received malformed packet. Size: " << rBufLen;
			is_flooding = 1;
			continue;
		}

		if (SenderAddr.sin_addr.S_un.S_addr != RecvAddr.sin_addr.S_un.S_addr) {
			LOG_IF(!is_flooding, INFO) << "Received a packet from an invalid IP ";
			is_flooding = 1;
			is_flooding = *(int*)0;
			continue;
		}
		
		// Prevent IPv6 & Bogus packets
		if (RecvBuf[0] >> 4 != 4) {
			continue;
		}

		int iphl = ((RecvBuf[0] & 0x0f) * 32) / 8; // This take the second half of a byte then *32/8 -> length of the ip header
		int totalSize = rBufLen - iphl - GRE_SIZE;
		int startSize = iphl + GRE_SIZE;
		if (iphl > 60 || iphl < 20) {
			LOG_IF(!is_flooding, INFO) << "Received a packet with a invalid IPHL: " << iphl;
			continue;
		}

		// Check for a valid IPv4 GRE Header (No key/sequence support)
		if (memcmp(RecvBuf + iphl, "\0\0\x08\0", GRE_SIZE) != 0) {
			LOG_IF(!is_flooding, INFO) << "Received a packet with an invalid GRE Header";
			is_flooding = 1;
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
			LOG_IF(!is_flooding, INFO) << "Received a packet with an invalid protocol: " << protocol;
			is_flooding = 1;
			continue;
		}

		BYTE* OutgoingPacket = WintunAllocateSendPacket(Session, totalSize);
		if (!OutgoingPacket)
		{
			DWORD lastError = GetLastError();
			LOG_IF(!is_flooding, WARNING) << "Could not allocate enough memory to send packet " << totalSize << " : " << lastError;
			is_flooding = 1;

			// Looks like we can't receive any more packets so we are going to restart the driver's session
			if (lastError == ERROR_HANDLE_EOF) {
				reset_adapter = true;
				LOG(WARNING) << "Restarting WinTun session due to an invalid packet.";

				WintunEndSession(Session);
				Session = WintunStartSession(Adapter, WINTUN_MAX_RING_CAPACITY / 2);

				if (!Session) {
					WintunCloseAdapter(Adapter);
					LOG(FATAL) << "Could not create session";
					exit(-1);
				}
				reset_adapter = false;
				LOG(INFO) << "Successfully restarted WinTun Session.";
			}
			continue;
		}
		is_flooding = 0;
		memcpy(OutgoingPacket, (RecvBuf + startSize), totalSize);
		WintunSendPacket(Session, OutgoingPacket);
	}
}

void GRE::sender(char* packet, unsigned int size) {
	int newSize = size + GRE_SIZE; // GRE size

	if (newSize > SEND_BUFFER)
	{
		LOG(WARNING) << "Sending buffer overflowed: " << newSize << " bytes";
		return;
	}

	// To modify the GRE Header (keys, sequences..) it'll need to be done here
	memcpy(sendBuf + GRE_SIZE, packet, size);

	sendto(s, sendBuf, newSize, 0, (SOCKADDR*)&RecvAddr, sizeof(RecvAddr));
}
