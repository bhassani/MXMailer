//https://gist.github.com/KunYi/15a71471ffcc6fb1f5f012d87dea84ea
//DNSQuery.c

// the code modify
// from https://support.microsoft.com/en-us/help/831226/how-to-use-the-dnsquery-function-to-resolve-host-names-and-host-addres
// build/testing with VisualStudio 2019 passed
// and only support IPV4
// DNSQuery.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#include <winsock2.h>  //winsock
#include <ws2tcpip.h>  //for tcpip api, inet_pton(), inet_ntop()
#include <windns.h>    //DNS api's
#include <stdio.h>     //standard i/o

#pragma comment(lib, "Ws2_32")
#pragma comment(lib, "Dnsapi")

// Usage of the program
void Usage(char *progname) {
  fprintf(stderr,
          "Usage\n%s -n [HostName|IP Address] -t [Type]  -s [DnsServerIp]\n",
          progname);
  fprintf(stderr,
          "Where:\n\t\"HostName|IP Address\" is the name or IP address of the "
          "computer ");
  fprintf(stderr, "of the record set being queried\n");
  fprintf(stderr,
          "\t\"Type\" is the type of record set to be queried A or PTR\n");
  fprintf(stderr,
          "\t\"DnsServerIp\"is the IP address of DNS server (in dotted decimal "
          "notation) ");
  fprintf(stderr, "to which the query should be sent\n");
  exit(1);
}

void ReverseIP(char *pIP, size_t size) {
  char seps[] = ".";
  char *token;
  char pIPSec[4][4];
  char *pTmp = {0};
  int i = 0;
  token = strtok_s(pIP, seps, &pTmp);
  while (token != NULL) {
    /* While there are "." characters in "string" */
    sprintf_s(pIPSec[i], "%s", token);
    /* Get next "." character: */
    token = strtok_s(NULL, seps, &pTmp);
    i++;
  }
  sprintf_s(pIP, size, "%s.%s.%s.%s.%s", pIPSec[3], pIPSec[2], pIPSec[1], pIPSec[0],
          "IN-ADDR.ARPA");
}

//  the main function
int __cdecl main(int argc, char *argv[]) {
  DNS_STATUS status;           // Return value of  DnsQuery_A() function.
  PDNS_RECORD pDnsRecord;      // Pointer to DNS_RECORD structure.
  PIP4_ARRAY pSrvList = NULL;  // Pointer to IP4_ARRAY structure.
  WORD wType;                  // Type of the record to be queried.
  char *pOwnerName = NULL;     // Owner name to be queried.
  char pReversedIP[255];       // Reversed IP address.
  char DnsServIp[255];         // DNS server ip address.
  DNS_FREE_TYPE freetype;
  freetype = DnsFreeRecordListDeep;
  IN_ADDR ipaddr;

  if (argc > 4) {
    for (int i = 1; i < argc; i++) {
      if ((argv[i][0] == '-') || (argv[i][0] == '/')) {
        switch (tolower(argv[i][1])) {
          case 'n':
            pOwnerName = argv[++i];
            break;
          case 't':
            if (!_stricmp(argv[i + 1], "A"))
              wType = DNS_TYPE_A;  // Query host records to resolve a name.
            else if (!_stricmp(argv[i + 1], "PTR")) {
              // pOwnerName should be in "xxx.xxx.xxx.xxx" format
              if (strlen(pOwnerName) <= 15) {
                // You must reverse the IP address to request a Reverse Lookup
                // of a host name.
                sprintf_s(pReversedIP, "%s", pOwnerName);
                ReverseIP(pReversedIP, sizeof(pReversedIP));
                pOwnerName = pReversedIP;
                wType =
                    DNS_TYPE_PTR;  // Query PTR records to resolve an IP address
              } else {
                Usage(argv[0]);
              }
            } else
              Usage(argv[0]);
            i++;
            break;

          case 's':
            // Allocate memory for IP4_ARRAY structure.
            pSrvList = (PIP4_ARRAY)LocalAlloc(LPTR, sizeof(IP4_ARRAY));
            if (!pSrvList) {
              printf("Memory allocation failed \n");
              exit(1);
            }
            if (argv[++i]) {
              strcpy_s(DnsServIp, argv[i]);
              pSrvList->AddrCount = 1;
              inet_pton(AF_INET, DnsServIp, &pSrvList->AddrArray[0]); // DNS server IPv4 address
              break;
            }

          default:
            Usage(argv[0]);
            break;
        }
      } else
        Usage(argv[0]);
    }
  } else
    Usage(argv[0]);

  // Calling function DnsQuery to query Host or PTR records
  status = DnsQuery(
      pOwnerName,              // Pointer to OwnerName.
      wType,                   // Type of the record to be queried.
      DNS_QUERY_BYPASS_CACHE,  // Bypasses the resolver cache on the lookup.
      pSrvList,                // Contains DNS server IP address.
      &pDnsRecord,             // Resource record that contains the response.
      NULL);                   // Reserved for future use.

  if (status) {
    if (wType == DNS_TYPE_A)
      printf("Failed to query the host record for %s and the error is %d \n",
             pOwnerName, status);
    else
      printf("Failed to query the PTR record and the error is %d \n", status);
  } else {
    if (wType == DNS_TYPE_A) {
      char ipv4Abuff[255] = {0};
      // convert the Internet network address into a string
      // in Internet standard dotted format.

      // for ipv4
      ipaddr.S_un.S_addr = (pDnsRecord->Data.A.IpAddress);
      inet_ntop(AF_INET, &ipaddr, ipv4Abuff, sizeof(ipv4Abuff));
      printf("The IP address of the host %s is %s \n", pOwnerName,
             ipv4Abuff);


      // Free memory allocated for DNS records.
      DnsRecordListFree(pDnsRecord, freetype);
    } else {
      printf("The host name is %s  \n", (pDnsRecord->Data.PTR.pNameHost));

      // Free memory allocated for DNS records.
      DnsRecordListFree(pDnsRecord, freetype);
    }
  }
  LocalFree(pSrvList);
  return 0;
}
