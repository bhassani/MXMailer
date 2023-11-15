/************************************
*
* Main code for the mailer
*
* Integrates the use of dnsapi.dll
* to query the dns to find MX server
* (Mail Exchanger server) of the user
*
* mail_it thread takes one paramater,
* which is the address.
*
************************************/
#define _WINSOCK_DEPRECATED_NO_WARNINGS 

#include <ws2tcpip.h>
#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <iphlpapi.h>
#include <windns.h>
#include <stdlib.h>
#pragma comment(lib, "iphlpapi.lib")
#pragma comment (lib, "ws2_32.lib")


/*
https://github.com/microsoft/Windows-classic-samples/blob/main/Samples/Win7Samples/netds/dns/dnsquery/DNSQuery.Cpp

*/

/*
USAGE:
const char *hostname = "somewebsite.com";
    unsigned long ipAddress = hostnameToLong(hostname);

    if (ipAddress != 0) {
        printf("IP Address: %lu\n", ipAddress);
    }
*/
unsigned long hostnameToLong(const char* hostname) {
    struct addrinfo hints, * result, * rp;
    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_INET; // Use AF_INET for IPv4, AF_INET6 for IPv6
    hints.ai_socktype = SOCK_STREAM; // Use SOCK_STREAM for TCP, SOCK_DGRAM for UDP

    int status = getaddrinfo(hostname, NULL, &hints, &result);
    if (status != 0) {
        fprintf(stderr, "getaddrinfo failed: %d\n", status);
        WSACleanup();
        return 0;
    }

    unsigned long ipAddress = 0;

    for (rp = result; rp != NULL; rp = rp->ai_next) {
        struct sockaddr_in* addr = (struct sockaddr_in*)rp->ai_addr;
        ipAddress = addr->sin_addr.s_addr;
        break; // Only consider the first address
    }

    freeaddrinfo(result);
    return ipAddress;
}

int resolve_hostname(char* host)
{
    struct addrinfo hints, * result, * rp;
    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_INET; // Use AF_INET for IPv4, AF_INET6 for IPv6
    hints.ai_socktype = SOCK_STREAM; // Use SOCK_STREAM for TCP, SOCK_DGRAM for UDP

    int status = getaddrinfo(host, NULL, &hints, &result);
    if (status != 0) {
        fprintf(stderr, "getaddrinfo failed: %d\n", status);
        WSACleanup();
        return 1;
    }

    for (rp = result; rp != NULL; rp = rp->ai_next) {
        struct sockaddr_in* addr = (struct sockaddr_in*)rp->ai_addr;
        printf("[resolve_hostname] IP Address: %s\n", inet_ntoa(addr->sin_addr));
    }

    freeaddrinfo(result);
    WSACleanup();

    return 0;
}

typedef DNS_STATUS(WINAPI* DNSQUERYA)(IN PCSTR pszName, IN WORD wType, IN DWORD Options, IN
    PIP4_ARRAY aipServers OPTIONAL, IN OUT PDNS_RECORD* ppQueryResults OPTIONAL, IN OUT PVOID*
    pReserved OPTIONAL);

int dns_connect(char* domain, char* toaddress)
{
    HINSTANCE hDnsapi;
    DNSQUERYA pDnsQuery_A;
    DNS_RECORD* pQueryResults, * pQueryRec;
    DNS_STATUS statusDns;
    char szDnsApi[] = "dnsapi.dll";
    hDnsapi = GetModuleHandleA(szDnsApi);
    if (hDnsapi == NULL) {
        hDnsapi = LoadLibraryA(szDnsApi);
        if (hDnsapi == NULL) return NULL;
    }
    pDnsQuery_A = (DNSQUERYA)GetProcAddress(hDnsapi, "DnsQuery_A");

        if (pDnsQuery_A == NULL) return NULL;
    statusDns = pDnsQuery_A(domain, DNS_TYPE_MX, DNS_QUERY_STANDARD, NULL, &pQueryResults,

        NULL);
    if (statusDns != ERROR_SUCCESS) return NULL;
    pQueryRec = pQueryResults;

    SOCKADDR_IN SockAddr;

    SOCKET hServer = socket(PF_INET, SOCK_STREAM, 0);
    if (hServer == INVALID_SOCKET) return FALSE;

    SockAddr.sin_addr.s_addr = hostnameToLong((char*)pQueryRec->Data.MX.pNameExchange);
    SockAddr.sin_family = AF_INET;
    SockAddr.sin_port = htons(25);

    printf("Hostname of MX server is:  %s\n", (char*)pQueryRec->Data.MX.pNameExchange);
    const char* hostname = (char*)pQueryRec->Data.MX.pNameExchange;
    unsigned long ipAddress = hostnameToLong(hostname);

    if (ipAddress != 0) {
        printf("[dns_connect]: IP Address: %lu\n", ipAddress);
    }

    resolve_hostname((char*)pQueryRec->Data.MX.pNameExchange);

    return 0;
}


#define MAX_DOMAIN 80
    int mailer(char* address)
    {
        WSADATA data;
        WSAStartup(MAKEWORD(2, 0), &data);
        char domain[MAX_DOMAIN], * p;
        for (p = address; *p && *p != '@'; p++);
        if (*p++ != '@') return 0;
        lstrcpyn((LPWSTR)domain, (LPCWSTR)p, MAX_DOMAIN - 1);

       dns_connect(domain, address);

 
        return 0;
    }

    int main()
    {
        mailer((char*)"test@google.com");

        WSACleanup();

        return 0;
    }
