#pragma once
#include <winsock2.h>
#include <Ws2tcpip.h>
#include <stdio.h>
#include <iostream>
#include <wintun.h>
#include "wintun_helper.h"
#include "easylogging++.h"

#define IPPROTO_GRE 47
#define GRE_SIZE 4
#define SEND_BUFFER 32768
extern bool reset_adapter;
extern WINTUN_SESSION_HANDLE Session;
extern WINTUN_ADAPTER_HANDLE Adapter;

class GRE
{
	SOCKET s{};
	sockaddr_in RecvAddr{};
	char* sendBuf;
public:
	GRE(const char* _server_ip, const char* _bind_ip) {
		// Pre-allocate sending buffer to avoid runtime allocation
		sendBuf = (char*)malloc(SEND_BUFFER);
		if (sendBuf == NULL) {
			LOG(FATAL) << "sendBuf: Could not allocate " << SEND_BUFFER << " bytes";
			return;
		}
		memcpy(sendBuf, "\0\0\x08\0", GRE_SIZE); // GRE size

		// GRE Server IP address
		RecvAddr.sin_family = AF_INET;
		RecvAddr.sin_port = htons(IPPROTO_GRE);
		inet_pton(AF_INET, _server_ip, &RecvAddr.sin_addr.s_addr);

		//-----------------
		WSADATA wsaData;
		int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
		if (iResult != NO_ERROR) {
			LOG(FATAL) << "WSAStartup failed: " << iResult;
			throw;
		}

		s = socket(AF_INET, SOCK_RAW, IPPROTO_GRE);
		if (s == INVALID_SOCKET) {
			LOG(FATAL) << "Socket creation failed: " << WSAGetLastError();
			throw;
		}

		struct sockaddr_in local{};
		local.sin_family = AF_INET;
		local.sin_port = htons(IPPROTO_GRE);
		inet_pton(AF_INET, _bind_ip, &local.sin_addr.s_addr);

		if (local.sin_addr.s_addr == INADDR_NONE || bind(s, (struct sockaddr*)&local, sizeof(local)) != 0)
		{
			LOG(FATAL) << "Binding failed: " << WSAGetLastError();
			throw;
		}

		WSASetIPUserMtu(s, 1476);
	}

	[[noreturn]] void receiver(HMODULE wintun);
	void sender(char* packet, unsigned int size);
};
