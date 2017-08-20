/*  processdumper: console utility for software analysis
 *  Copyright(C) 2017  Peter Bohning
 *  This program is free software : you can redistribute it and / or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>. */
#include <stdio.h>
#include <winsock2.h>
#include "ipcsocket.h"

HANDLE thread = NULL;

DWORD WINAPI IPCThread(LPVOID param);
int listen_loop(SOCKET sock);

void unceremonious_exit(void)
{
	if(thread)
		TerminateThread(thread, -1);		//does not allow proper thread cleanup...
}

uint16_t setup_local_socket(void)
{
	WSADATA wsaData;
	SOCKET ListenSocket;
	sockaddr_in service;
	uint16_t port;
	DWORD thread_id;

	memset(&wsaData, 0, sizeof(WSADATA));
	printf("so....\n");
	int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if(iResult != NO_ERROR) {
		wprintf(L"WSAStartup failed with error: %ld\n", iResult);
		return 1;
	}
	printf("The fuck\n");
	ListenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if(ListenSocket == INVALID_SOCKET) {
		wprintf(L"socket failed with error: %ld\n", WSAGetLastError());
		//WSAEADDRNOTAVAIL 10049
		WSACleanup();
		return 1;
	}
	
	port = 29017;
	memset(&service, 0, sizeof(sockaddr_in));
	service.sin_family = AF_INET;
	service.sin_addr.s_addr = inet_addr("127.0.0.1");
	service.sin_port = htons(port);

	if(bind(ListenSocket, (SOCKADDR *)& service, sizeof(service)) == SOCKET_ERROR) {
		wprintf(L"bind failed with error: %ld\n", WSAGetLastError());
		closesocket(ListenSocket);
		WSACleanup();
		return 1;
	}

	if(listen(ListenSocket, 1) == SOCKET_ERROR) {
		wprintf(L"listen failed with error: %ld\n", WSAGetLastError());
		closesocket(ListenSocket);
		WSACleanup();
		return 1;
	}
	printf("starting thread\n");
	thread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)IPCThread, &ListenSocket, 0, &thread_id);
	if(!thread)
	{
		fprintf(stderr, "inject process CreateRemoteThread failed (%d)\n", GetLastError());
		closesocket(ListenSocket);
		return -1;
	}

	return port;
}

DWORD WINAPI IPCThread(LPVOID param)
{
	SOCKET ListenSocket = *(SOCKET *)param;
	SOCKET AcceptSocket;

	wprintf(L"Waiting for client to connect...\n");

	AcceptSocket = accept(ListenSocket, NULL, NULL);
	if(AcceptSocket == INVALID_SOCKET) {
		wprintf(L"accept failed with error: %ld\n", WSAGetLastError());
		closesocket(ListenSocket);
		WSACleanup();
		return 1;
	}
	else
		wprintf(L"Client connected.\n");

	closesocket(ListenSocket);

	listen_loop(AcceptSocket);

	closesocket(AcceptSocket);

	WSACleanup();
	return 0;
}

int listen_loop(SOCKET sock)
{
#define DEFAULT_BUFLEN 512

	char recvbuf[DEFAULT_BUFLEN];
	int iResult, iSendResult;
	int recvbuflen = DEFAULT_BUFLEN;
	int i;

	do {

		iResult = recv(sock, recvbuf, recvbuflen, 0);
		if(iResult > 0) {
			printf("Bytes received: %d\n", iResult);
			for(i = 0; i < iResult; i++)
				printf("%02x", (unsigned char)recvbuf[i]);
			printf("\n\n");
			printf("%d : %d\n", *(uint16_t *)&(recvbuf[0]), *(uint16_t *)&(recvbuf[2]));
			/*iSendResult = send(sock, recvbuf, iResult, 0);
			if(iSendResult == SOCKET_ERROR) {
				printf("send failed: %d\n", WSAGetLastError());
				return -1;
			}
			printf("Bytes sent: %d\n", iSendResult);*/
		}
		else if(iResult == 0)
			printf("Connection closing...\n");
		else {
			printf("recv failed: %d\n", WSAGetLastError());
			return -1;
		}

	} while(iResult > 0);

	SetEvent(sync_event);

	return 0;
}
