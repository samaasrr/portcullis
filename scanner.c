#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <process.h>
#include "scanner.h"
#include "banner.h"

ScanResult results[MAX_RESULTS];
HANDLE thread_semaphore;

const char* get_service(int port) {
    switch(port) {
        case 21:    return "FTP";
        case 22:    return "SSH";
        case 23:    return "Telnet";
        case 25:    return "SMTP";
        case 53:    return "DNS";
        case 80:    return "HTTP";
        case 110:   return "POP3";
        case 111:   return "RPC";
        case 135:   return "MSRPC";
        case 139:   return "NetBIOS";
        case 143:   return "IMAP";
        case 443:   return "HTTPS";
        case 445:   return "SMB";
        case 993:   return "IMAPS";
        case 995:   return "POP3S";
        case 1723:  return "PPTP";
        case 3306:  return "MySQL";
        case 3389:  return "RDP";
        case 5432:  return "PostgreSQL";
        case 5900:  return "VNC";
        case 6379:  return "Redis";
        case 8080:  return "HTTP-Alt";
        case 8443:  return "HTTPS-Alt";
        case 9200:  return "Elasticsearch";
        case 27017: return "MongoDB";
        default:    return "Unknown";
    }
}

int resolve_host(const char* host, char* ip_out) {
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(host, NULL, &hints, &res) != 0) return 0;

    struct sockaddr_in* addr = (struct sockaddr_in*)res->ai_addr;
    inet_ntop(AF_INET, &addr->sin_addr, ip_out, INET_ADDRSTRLEN);
    freeaddrinfo(res);
    return 1;
}

unsigned __stdcall scan_thread(void* arg) {
    ThreadArgs* args = (ThreadArgs*)arg;

    SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) {
        ReleaseSemaphore(thread_semaphore, 1, NULL);
        free(args);
        return 0;
    }

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(args->port);
    inet_pton(AF_INET, args->ip, &addr.sin_addr);

    DWORD timeout = TIMEOUT_MS;
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));

    int result = connect(sock, (struct sockaddr*)&addr, sizeof(addr));
    closesocket(sock);

    int idx = args->index;
    results[idx].port = args->port;
    strcpy(results[idx].ip, args->ip);
    strcpy(results[idx].service, get_service(args->port));

    if (result == 0) {
        results[idx].open = 1;
        grab_banner(args->ip, args->port, results[idx].banner);
    } else {
        results[idx].open = 0;
    }

    ReleaseSemaphore(thread_semaphore, 1, NULL);
    free(args);
    return 0;
}