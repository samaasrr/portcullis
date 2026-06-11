#ifndef SCANNER_H
#define SCANNER_H

#include <winsock2.h>
#include <ws2tcpip.h>

#define TIMEOUT_MS  500
#define MAX_THREADS 100
#define MAX_RESULTS 65536
#define MAX_BANNER  256

typedef struct {
    char ip[INET_ADDRSTRLEN];
    int  port;
    int  open;
    char service[32];
    char banner[MAX_BANNER];
} ScanResult;

typedef struct {
    char ip[INET_ADDRSTRLEN];
    int  port;
    int  index;
} ThreadArgs;

extern ScanResult results[MAX_RESULTS];
extern HANDLE thread_semaphore;

const char* get_service(int port);
unsigned __stdcall scan_thread(void* arg);
int resolve_host(const char* host, char* ip_out);

#endif