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

#include <ws2tcpip.h>
#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <iphlpapi.h>
#pragma comment(lib, "iphlpapi.lib")
#pragma comment (lib, "ws2_32.lib")
#include <windns.h>
#include <stdlib.h>
#include <iosfwd>
#include <fstream>
using namespace std;

/*
https://github.com/microsoft/Windows-classic-samples/blob/main/Samples/Win7Samples/netds/dns/dnsquery/DNSQuery.Cpp

*/

/*
Deprecated Function:
static unsigned long resolve(char *hostname)
{
    unsigned long ip = inet_addr(hostname);
    if (ip == 0xFFFFFFFF || (ip == 0 && hostname[0] != '0')) {
    struct hostent *h = gethostbyname(hostname);
    if (h != NULL)
    ip = *(unsigned long *)h->h_addr_list[0];
    }
    if (ip == 0xFFFFFFFF) ip = 0;
    return ip;
}*/

static unsigned long resolve(char *hostname)
{
    unsigned long ip = inet_addr(hostname);
    if (ip == 0xFFFFFFFF || (ip == 0 && hostname[0] != '0'))
    {
        struct addrinfo hints, *result, *rp;
        ZeroMemory(&hints, sizeof(hints));
        hints.ai_family = AF_INET; // Use AF_INET for IPv4, AF_INET6 for IPv6
        hints.ai_socktype = SOCK_STREAM; // Use SOCK_STREAM for TCP, SOCK_DGRAM for UDP
        int status = getaddrinfo(hostname, NULL, &hints, &result);
        
        /* implementation 2
        for (rp = result; rp != NULL; rp = rp->ai_next)
        {
            struct sockaddr_in *addr = (struct sockaddr_in *)rp->ai_addr;
            printf("IP Address: %s\n", inet_ntoa(addr->sin_addr));
        } */
    }
    
    if (ip == 0xFFFFFFFF)
    {
        ip = 0;
    }
    freeaddrinfo(result);
    return ip;
}

/*
USAGE:
const char *hostname = "mx.somewebsite.com";
    unsigned long ipAddress = hostnameToLong(hostname);

    if (ipAddress != 0) {
        printf("IP Address: %lu\n", ipAddress);
    }
*/
unsigned long hostnameToLong(const char *hostname) {
    struct addrinfo hints, *result, *rp;
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
        struct sockaddr_in *addr = (struct sockaddr_in *)rp->ai_addr;
        ipAddress = addr->sin_addr.s_addr;
        break; // Only consider the first address
    }

    freeaddrinfo(result);
    return ipAddress;
}

typedef DNS_STATUS (WINAPI *DNSQUERYA)(IN PCSTR pszName, IN WORD wType, IN DWORD Options, IN
PIP4_ARRAY aipServers OPTIONAL, IN OUT PDNS_RECORD *ppQueryResults OPTIONAL, IN OUT PVOID *
pReserved OPTIONAL);

int dns_connect(char *domain, char * toaddress)
{
    HINSTANCE hDnsapi;
    DNSQUERYA pDnsQuery_A;
    DNS_RECORD *pQueryResults, *pQueryRec;
    DNS_STATUS statusDns;
    char szDnsApi[] = "dnsapi.dll";
    hDnsapi = GetModuleHandle(szDnsApi);
    if (hDnsapi == NULL) {
    hDnsapi = LoadLibrary(szDnsApi);
    if (hDnsapi == NULL) return NULL;
    }
    pDnsQuery_A = (DNSQUERYA)GetProcAddress(hDnsapi, "DnsQuery_A");
     Mailer.cpp

    if (pDnsQuery_A == NULL) return NULL;
    statusDns = pDnsQuery_A(domain, DNS_TYPE_MX, DNS_QUERY_STANDARD, NULL, &pQueryResults,

    NULL);
    if (statusDns != ERROR_SUCCESS) return NULL;
    pQueryRec=pQueryResults;

    SOCKADDR_IN SockAddr;

    hServer = socket(PF_INET,SOCK_STREAM,0);
    if (hServer==INVALID_SOCKET) return FALSE;

    SockAddr.sin_addr.s_addr = resolve(pQueryRec->Data.MX.pNameExchange);
    SockAddr.sin_family = AF_INET;
    SockAddr.sin_port = htons(25);

    if (connect(hServer,(PSOCKADDR)&SockAddr,sizeof(SockAddr))) return FALSE;

    recvbuff();
    sendmail(toaddress);
    return 0;
}
/* obtains MX server by recursively, manually, querying user's DNS server */

int mx_get(char *d_omain, char *to_address)
{
  int iTimeout = 0;
  DWORD iIP;
  FIXED_INFO * FixedInfo;
  ULONG ulOutBufLen;
  DWORD dwRetVal;

  FixedInfo = (FIXED_INFO *) GlobalAlloc( GPTR, sizeof( FIXED_INFO ) );

  ulOutBufLen = sizeof( FIXED_INFO );
  //////////////////////////////
  //obtain user's current DNS server
  if( ERROR_BUFFER_OVERFLOW == GetNetworkParams( FixedInfo, &ulOutBufLen ) ) {

  GlobalFree( FixedInfo );
  FixedInfo = (FIXED_INFO *) GlobalAlloc( GPTR, ulOutBufLen );
  }
  if ( dwRetVal = GetNetworkParams( FixedInfo, &ulOutBufLen ) ) {
  iTimeout = 3000;
  iIP=resolve(FixedInfo->DnsServerList.IpAddress.String);

  printf("\r\n");
  MX mx = MxRecursiveGet(d_omain,iIP,iTimeout);

  if (!mx.dwNumReplies) {
  return 1;
  }


  hServer = socket(PF_INET,SOCK_STREAM,0);
  if (hServer==INVALID_SOCKET) return FALSE;

  SOCKADDR_IN SockAddr;
  SockAddr.sin_addr.s_addr = resolve(mx.mxReplies->sHostname);
  SockAddr.sin_family = AF_INET;
  SockAddr.sin_port = htons(25);

  if (connect(hServer,(PSOCKADDR)&SockAddr,sizeof(SockAddr))) return FALSE;

  recvbuff();
  sendmail(to_address);
  MxClearBuffer(&mx);

  return 0;
}
  
#define MAX_DOMAIN 80
int mailer(char *address)
{
    OSVERSIONINFO osvi;
    BOOL bResult;
    WSADATA data;
    WSAStartup(MAKEWORD(2,0), &data);
    char domain[MAX_DOMAIN], *p;
    for (p=address; *p && *p != '@'; p++);
    if (*p++ != '@') return 0;
    lstrcpyn(domain, p, MAX_DOMAIN-1);
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
    bResult=GetVersionEx(&osvi); //obtain OS of comp
    if(!bResult)
    return 606;
    if((osvi.dwPlatformId != VER_PLATFORM_WIN32_NT) && (osvi.dwPlatformId != VER_PLATFORM_WIN32_WINDOWS))
    {
      //if for some reason not NT,2k,XP or 98,95,ME return
      return 607;
    }
    if(osvi.dwPlatformId==VER_PLATFORM_WIN32_NT) //if OS is XP,2k or NT use the dnsapi.dll library to obtain mx server
    {
      dns_connect(domain,address);
    }
    else {
      mx_get(domain,address); //otherwise manually query for the MX server
    }
    return 0;
}

DWORD _stdcall mail_it(LPVOID pv) //mailer thread
{
    mailer((char *)pv);
    return 0;
}
