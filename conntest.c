/*

  conntest.c

  Copyright (c) 1999 - 2010 Pekka Riikonen, priikone@iki.fi.

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#ifdef WIN32
#define SYSLOG(x)
#define strcasecmp strcmp
#define snprintf _snprintf
#define usleep(x) (Sleep(x / 1000))
#define sleep(x) (Sleep(x * 1000))
#include <winsock2.h>
#include <windows.h>
#else
#define SYSLOG(x) syslog x
#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <syslog.h>
#endif

#include "conntest.h"
#include "ike.h"

char *e_host = NULL;
char *e_ip_start = NULL;
char *e_ip_end = NULL;
char *e_lip = NULL;
char *e_lip_start = NULL;
char *e_lip_end = NULL;
int e_lip_s = 1;
int e_lip_e = 0;
int e_port = 9;
int e_lport = 0;
int e_num_conn;
int e_data_len;
int e_send_loop;
int e_flood, e_data_flood;
int e_sleep = 1000;
int e_threads;
int e_proto;
int e_do_ike = 0;
int e_ike_attack = 0;
char *e_ike_identity = NULL;
int e_ike_group = 2;
int e_ike_auth = 1;
char *e_header = NULL;
int e_header_len = 0;
int e_sock_type = PF_INET;
int e_sock_proto = 0;
int e_unique = 0;
int e_random_ip = 0;
int e_pmtu = -1;
int e_ttl = -1;
int e_time;
int e_want_ip6 = 0;
unsigned int e_quiet = 0;

#define MAX_SOCKETS 20000

static unsigned char ip4_header[20] = "\x45\x00\x00\x00\x00\x00\x00\x00\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";

struct sockets {
  int sockets[MAX_SOCKETS];
  unsigned char ip4h[MAX_SOCKETS][20];
  c_sockaddr udp_dest[MAX_SOCKETS];
  int num_sockets;
};

#define PUT32(d, n)							\
do {									\
  (d)[0] = n >> 24 & 0xff;						\
  (d)[1] = n >> 16 & 0xff;						\
  (d)[2] = n >> 8 & 0xff;						\
  (d)[3] = n & 0xff;							\
} while(0)

#define SWAB32(l) ((unsigned int)					\
   (((unsigned int)(l) & (unsigned int)0x000000FFUL) << 24) |		\
   (((unsigned int)(l) & (unsigned int)0x0000FF00UL) << 8)  |		\
   (((unsigned int)(l) & (unsigned int)0x00FF0000UL) >> 8)  |		\
   (((unsigned int)(l) & (unsigned int)0xFF000000UL) >> 24))

#define SIZEOF_SOCKADDR(so) ((so).sa.sa_family == AF_INET6 ?    \
  sizeof((so).sin6) : sizeof((so).sin))

void thread_data_send(struct sockets *s, int offset, int num,
                      int loop, void *data, int datalen, int flood);

int is_ip6(const char *addr)
{
  /* XXX does this work with all kinds of IPv6 addresses? */
  while (*addr && *addr != '%') {
    if (*addr != ':' && !isxdigit((int)*addr))
      return 0;
    addr++;
  }

  return 1;
}

int c_gethostbyname(char *name, int want_ipv6, char *addr, int addr_size)
{
  struct addrinfo hints, *ai, *tmp, *ip4 = NULL, *ip6 = NULL;

  memset(&hints, 0, sizeof(hints));
  hints.ai_socktype = SOCK_STREAM;
  if (getaddrinfo(name, NULL, &hints, &ai))
    return 0;

  for (tmp = ai; tmp; tmp = tmp->ai_next) {
    if (tmp->ai_family == AF_INET6) {
      ip6 = tmp;
      if (ip4)
        break;
      continue;
    }
    if (tmp->ai_family == AF_INET) {
      ip4 = tmp;
      if (ip6)
        break;
      continue;
    }
  }

  tmp = (want_ipv6 ? (ip6 ? ip6 : ip4) : (ip4 ? ip4 : ip6));
  if (!tmp) {
    freeaddrinfo(ai);
    return 0;
  }

  if (getnameinfo(tmp->ai_addr, tmp->ai_addrlen, addr,
                  addr_size, NULL, 0, NI_NUMERICHOST)) {
    freeaddrinfo(ai);
    return 0;
  }

  freeaddrinfo(ai);
  return 1;
}

int addr2bin(const char *addr, void *bin, size_t bin_len, int *dev)
{
  int ret = 0;

  if (!is_ip6(addr)) {
    /* IPv4 address */
    struct in_addr tmp;

    ret = inet_aton(addr, &tmp);
    if (!ret)
      return 0;

    memcpy(bin, (unsigned char *)&tmp.s_addr, 4);
    *dev = 0;
  } else {
    struct addrinfo hints, *ai;
    c_sockaddr *s;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET6;
    if (getaddrinfo(addr, NULL, &hints, &ai))
      return 0;

    if (ai) {
      s = (c_sockaddr *)ai->ai_addr;
      memcpy(bin, &s->sin6.sin6_addr, sizeof(s->sin6.sin6_addr));
      *dev = s->sin6.sin6_scope_id;
      freeaddrinfo(ai);
    }

    ret = 1;
  }

  return ret != 0;
}

int set_sockaddr(c_sockaddr *addr, const char *ip_addr, int port, int *family,
		 unsigned char *iphdr, int local)
{
  int len, dev;

  memset(addr, 0, sizeof(*addr));

  /* Check for IPv4 and IPv6 addresses */
  if (ip_addr) {
    if (!is_ip6(ip_addr)) {
      /* IPv4 address */
      len = sizeof(addr->sin.sin_addr);
      if (!addr2bin(ip_addr,
                    (unsigned char *)&addr->sin.sin_addr.s_addr, len, &dev))
        return 0;
      addr->sin.sin_family = AF_INET;
      addr->sin.sin_port = port ? htons(port) : 0;
      *family = AF_INET;

      /* Update raw IP header */
      local = local ? 12 : 16;
      memcpy(iphdr + local, &addr->sin.sin_addr.s_addr, 4);
    } else {
      /* IPv6 address */
      len = sizeof(addr->sin6.sin6_addr);
      if (!addr2bin(ip_addr,
                    (unsigned char *)&addr->sin6.sin6_addr, len, &dev))
        return 0;
      addr->sin6.sin6_family = AF_INET6;
      addr->sin6.sin6_port = port ? htons(port) : 0;
      addr->sin6.sin6_scope_id = dev; 
     *family = AF_INET6;

      /* Update raw IP header */
      /* XXX TODO */
    }
  } else {
    /* Any address */
    addr->sin.sin_family = *family;
    addr->sin.sin_addr.s_addr = INADDR_ANY;
    if (port)
      addr->sin.sin_port = htons(port);
  }

  return 1;
}


/* Convert HEX string to binary data */

unsigned char *hex2data(const char *hex, int *ret_data_len)
{
  char *cp = (char *)hex;
  unsigned char *data;
  unsigned char l, h;
  int i;

  data = malloc(strlen(hex) / 2);
  if (!data)
    return NULL;

  for (i = 0; i < strlen(hex) / 2; i++) {
    h = *cp++;
    l = *cp++;

    h -= h < 'A' ? '0' : 'A' - 10;
    l -= l < 'A' ? '0' : 'A' - 10;

    data[i] = (h << 4) | (l & 0xf);
  }

  *ret_data_len = i;
  return data;
}

/* Set socket option */
int set_sockopt(int socket, int t, int s, int val)
{
  int option = val;
  if (setsockopt(socket, t, s,
                 (void *) &option,
                 sizeof(int)) < 0)
    {
      fprintf(stderr, "setsockopt(): %s\n", strerror(errno));
      return -1;
    }
  return 0;
}

/* Creates a new TCP/IP or UDP/IP connection. Returns the newly created
   socket or -1 on error. */

int create_connection(int port, char *dhost, int index,
		      struct sockets *sockets)
{
  int i, sock;
  c_sockaddr desthost, srchost;
  char a[64];
#ifdef WIN32
  unsigned long addr;
#endif
  unsigned char *ip4h = sockets->ip4h[index];

  memset(a, 0, sizeof(a));

  memcpy(ip4h, ip4_header, 20);

  /* If raw protocol was given the caller must provide the IP header (or
     part of it). */
  if (e_sock_proto == IPPROTO_RAW)
    memcpy(ip4h, e_header, e_header_len < 20 ? e_header_len : 20);

  /* Do host look up */
  if (dhost) {
#ifndef WIN32
    if (!c_gethostbyname(dhost, e_want_ip6, a, sizeof(a))) {
      fprintf(stderr, "Network (%s) is unreachable\n", dhost);
      return -1;
    }
    if (!set_sockaddr(&desthost, a, port, &e_sock_type, ip4h, 0)) {
      fprintf(stderr, "Error setting socket address: %s\n", strerror(errno));
      return -1;
    }
#else
    addr = inet_addr(dhost);
    memcpy(&desthost.sin_addr, &addr, sizeof(desthost.sin_addr));
    PUT32(ip4h + 16, addr);
#endif
  } else {
    /* Any address */
    set_sockaddr(&desthost, NULL, port, &e_sock_type, NULL, 0);
  }

  /* create the connection socket */
  sock = socket(e_sock_type, e_proto, e_sock_proto);
  if (sock < 0) {
    fprintf(stderr, "socket(): %s\n", strerror(errno));
    return -1;
  }

  /* If raw sockets and local IP is selected or is provided in data, set
     IP_HRDINCL sockopt so we can specify our own IP. */
  if (e_proto == SOCK_RAW && (e_lip || e_sock_proto == IPPROTO_RAW)) {
#ifndef WIN32
    set_sockopt(sock, IPPROTO_IP, IP_HDRINCL, 1);
#endif
    if (e_sock_proto != IPPROTO_RAW)
      ip4h[9] = e_sock_proto;
  }

  /* Bind to local IP and port */
  if (e_lip || e_lport) {
#ifndef WIN32
    if (e_lip) {
      if (!c_gethostbyname(e_lip, e_want_ip6, a, sizeof(a))) {
        fprintf(stderr, "Network (%s) is unreachable\n", e_lip);
        return -1;
      }
      if (!set_sockaddr(&srchost, a, e_lport, &e_sock_type, ip4h, 1)) {
        fprintf(stderr, "Error setting socket address: %s\n", strerror(errno));
        return -1;
      }
    } else {
      /* Any address */
      set_sockaddr(&srchost, NULL, e_lport, &e_sock_type, NULL, 0);
    }
#else
    if (e_lip) {
      addr = inet_addr(e_lip);
      memcpy(&srchost.sin_addr, &addr, sizeof(srchost.sin_addr));
      PUT32(ip4h + 12, addr);
    }
#endif
    if (e_proto != SOCK_RAW) {
      if (bind(sock, (struct sockaddr *)&srchost, sizeof(srchost))) {
        fprintf(stderr, "Could not bind to %s:%d\n", e_lip, e_lport);
        exit(1);
      }
    }
  }

  /* Set PMTU discovery policy */
#ifndef WIN32
  if (e_pmtu != -1) {
    set_sockopt(sock, SOL_IP, IP_MTU_DISCOVER, e_pmtu);
    if (e_proto == SOCK_RAW && e_pmtu == 3)
      ip4h[6] = 0x40;
  }

  /* Set TTL */
  if (e_ttl != -1) {
    if (e_ttl)
      set_sockopt(sock, SOL_IP, IP_TTL, e_ttl);
    if (e_proto == SOCK_RAW)
      ip4h[8] = e_ttl;
  }
#endif

  /* connect to the host */
  if (e_proto == SOCK_STREAM) {
    if (!e_quiet)
      fprintf(stderr, "Connecting to port %d of host %s (%s).", port,
	      dhost ? dhost : "N/A", dhost ? a : "N/A");

    i = connect(sock, &desthost.sa, SIZEOF_SOCKADDR(desthost));
    if (i < 0) {
      fprintf(stderr, "\nconnect(): %s\n", strerror(errno));
      shutdown(sock, 2);
      close(sock);
    } else {
      if (!e_quiet)
	fprintf(stderr, " Done.\n");
      set_sockopt(sock, IPPROTO_TCP, TCP_NODELAY, 1);
      sockets->sockets[index] = sock;
      set_sockopt(sock, SOL_SOCKET, SO_BROADCAST, 1);
#if defined(SO_SNDBUF)
      if (set_sockopt(sock, SOL_SOCKET, SO_SNDBUF, 1000000) < 0)
	set_sockopt(sock, SOL_SOCKET, SO_SNDBUF, 65535);
#endif /* SO_SNDBUF */
#if defined(SO_SNDBUFFORCE)
      if (set_sockopt(sock, SOL_SOCKET, SO_SNDBUFFORCE, 1000000) < 0)
	set_sockopt(sock, SOL_SOCKET, SO_SNDBUFFORCE, 65535);
#endif /* SO_SNDBUFFORCE */
      return sock;
    }
  } else {
    if (!e_quiet)
      fprintf(stderr, "Sending data to port %d of host %s (%s).\n", port,
	      dhost ? dhost : "N/A", dhost ? a : "N/A");
    sockets->sockets[index] = sock;
    memcpy(&sockets->udp_dest[index], &desthost, sizeof(desthost));
    set_sockopt(sock, SOL_SOCKET, SO_BROADCAST, 1);
#if defined(SO_SNDBUF)
    if (set_sockopt(sock, SOL_SOCKET, SO_SNDBUF, 1000000) < 0)
      set_sockopt(sock, SOL_SOCKET, SO_SNDBUF, 65535);
#endif /* SO_SNDBUF */
#if defined(SO_SNDBUFFORCE)
    if (set_sockopt(sock, SOL_SOCKET, SO_SNDBUFFORCE, 1000000) < 0)
      set_sockopt(sock, SOL_SOCKET, SO_SNDBUFFORCE, 65535);
#endif /* SO_SNDBUFFORCE */
    return sock;
  }

  return -1;
}

/* Closes the connection */

int close_connection(int sock)
{
  shutdown(sock, 2);
  close(sock);

  return 0;
}

/* Sends data to the host. */

int send_data(struct sockets *s, int index, void *data, unsigned int len)
{
  int ret, i;
  int sock = s->sockets[index];
  unsigned char *ip4h = s->ip4h[index];
  c_sockaddr *udp = &s->udp_dest[index];
  unsigned char *d = data;

  /* If requested, make data unique */
  if (e_unique)
    for (i = e_header_len; i < (len - e_header_len) - 1; i++)
      d[i] ^= d[i + 1] ^ ((d[i] + 0x9d2c5681UL) * 1812433253UL) >> 11;

  /* If raw sockets and local IP is specified, now copy the IP header */
  if (e_proto == SOCK_RAW && (e_lip || e_sock_proto == IPPROTO_RAW))
    memcpy(d, ip4h, 20);

  /* Randomize source IP if requested */
  if (e_random_ip) {
    ip4h[12] = d[12] ^= (e_time ^ (e_time >> 11));
    ip4h[13] = d[13] ^= d[12] ^ ((d[13] << 7) & 0x9d2c5680UL);
    ip4h[14] = d[14] ^= d[13] ^ ((d[14] << 15) & 0xefc60000UL);
    ip4h[15] = d[15] ^= d[14] ^ (d[15] >> 18);
    if (d[12] == 0 || d[12] == 224 || d[12] == 255)
      ip4h[12] = d[12] = 1;
    if (d[15] == 255)
      ip4h[15] = d[15] = 1;
    e_time += 2749;
  }

  /* Source IP range if requested */
  if (e_lip_start && e_lip_end) {
    if (e_lip_s > e_lip_e)
      e_lip_s = atoi(strrchr(e_lip_start, '.') + 1);
    ip4h[15] = d[15] = e_lip_s++;
  }

  if (e_proto == SOCK_STREAM) {
    ret = send(sock, data, len, 0);
    if (ret < 0) {
      fprintf(stderr, "send(): %s\n", strerror(errno));
      return -1;
    }
  } else {
    ret = sendto(sock, data, len, 0, &udp->sa, SIZEOF_SOCKADDR(*udp));
    if (ret < 0) {
      fprintf(stderr, "sendto(): %s\n", strerror(errno));
      fprintf(stderr, "%x.%x.%x.%x\n", ip4h[12], ip4h[13], ip4h[14], ip4h[15]);
      return -1;
    }
  }

  return 0;
}

void usage()
{
  printf("Usage: conntest OPTIONS\n");
  printf("Options:\n");
  printf("  -h <hostname>   Destination IP or host name\n");
  printf("  -H <IP-IP>      Destination IP range (eg. 10.2.1.1-10.2.1.254)\n");
  printf("  -p <port>       Destination port\n");
  printf("  -L <IP>         Local IP to use if possible (default: auto)\n");
  printf("  -R <IP-IP>      Local IP range when -P is 'raw' or integer value\n");
  printf("  -r              Use random source IP when -P is 'raw' or integer value\n");
  printf("  -K <port>       Local port to use if possible (default: auto)\n");
  printf("  -P <protocol>   Protocol, 'tcp', 'udp', 'raw' or integer value\n");
  printf("  -c <number>     Number of connections (default: 1)\n");
  printf("  -d <length>     Length of data to transmit, bytes (default: 1024)\n");
  printf("  -D <string>     Data header to packet, if starts with 0x string must be HEX\n");
  printf("  -Q <file>       Data from file, if -P is 'raw' data must include IP header\n");
  printf("  -l <number>     Number of loops to send data (default: infinity)\n");
  printf("  -t <number>     Number of threads used in data sending (default: single)\n");
  printf("  -n <msec>       Data send interval (ignored with -F) (default: 1000 msec)\n");
  printf("  -m <pmtu>       PMTU discovery: 0 no PMTU, 2 do PMTU, 3 set DF, ignore PMTU\n");
  printf("  -T <ttl>        Set TTL, 0-255, can be used with raw protocols as well\n");
  printf("  -u              Each packet will have unique data payload\n");
  printf("  -f              Flood, no delays creating connections (default: undefined)\n");
  printf("  -F              Flood, no delays between data sends (default: undefined)\n");
  printf("  -q              Quiet, don't display anything\n");
  printf("  -6              Use/prefer IPv6 addresses\n");
  printf("  -V              Display version and help, then exit\n");
  printf("\n  Protocols:\n");
  printf("  -A <protocol>   Do <protocol> attack\n");
  printf("     ike-aggr     IKE Diffie-Hellman attack with aggressive mode\n");
  printf("     ike-mm       IKE Main Mode double packet attack\n");
  printf("     -i <ip>      Aggressive mode identity (default: 0.0.0.0) (ike-aggr only)\n");
  printf("     -g <group>   IKE group (default: 2)\n");
  printf("     -a <auth>    Auth method (psk, rsa, dss, xauth-psk, xauth-rsa, xauth-dss)\n");
  printf("\n");
  printf("Examples:\n");
  printf("  - Send UDP data to host 10.2.1.7 on port 1234:\n");
  printf("      conntest -h 10.2.1.7 -P udp -p 1234\n");
  printf("  - Open TCP connection to 10.2.1.7 on port 80 and send HTTP request:\n");
  printf("      conntest -h 10.2.1.7 -P tcp -p 80 -D \"GET / HTTP 1.1\"\n");
  printf("  - Open TCP connection to fe80::250:56ff:fec0:8 via eth1\n");
  printf("      conntest -h fe80::250:56ff:fec0:8%%eth1 -P tcp -p 80\n");
  printf("  - Send bogus TCP packets to 10.2.1.7 from random IP (no TCP handshake):\n");
  printf("      conntest -h 10.2.1.7 -r -P 6\n");
  printf("  - Send random 300 byte ESP packets to host 10.2.1.7 from IP 1.1.1.1:\n");
  printf("      conntest -h 10.2.1.7 -L 1.1.1.1 -P 50 -u -d 300\n");
  printf("  - Send bogus IP packet from data file, which includes IP header too:\n");
  printf("      conntest -P raw -Q packet.dat\n");
  printf("  - Send bogus IKE packets from random source IP, -D provides partial UDP\n");
  printf("    header which sets local and remote port to 500 (01f4):\n");
  printf("      conntest -h 1.1.1.1 -r -P 17 -D 0x01f401f4\n");
  printf("  - Send ICMP packets to 1.1.1.1, random source IP (three ways to do same):\n");
  printf("      conntest -P 1 -r -h 1.1.1.1\n");
  printf("      conntest -P raw -r -D 0x45000000000000000001 -h 1.1.1.1\n");
  printf("      conntest -P raw -r -D 0x4500000000000000000100000000000001010101\n");

  exit(0);
}

static void *memdup(void *x, int l)
{
  void *tmp = malloc(l);
  memcpy(tmp, x, l);
  return tmp;
}

#define GET_SEPARATED(x, s, ret1, ret2)					\
do {									\
  if (strchr((x), (s)))							\
    {									\
      char _s[2];							\
      int _len;								\
      snprintf(_s, sizeof(_s), "%c", (s));				\
      _len = strcspn((x), _s);						\
      (ret1) = memdup((x), _len);					\
      (ret2) = memdup((x) + _len + 1, strlen((x) + _len + 1));	\
    }									\
} while(0)

int main(int argc, char **argv)
{
  int i, k;
  char *data, opt;
  int len;
  struct sockets s;
  char fdata[32000];
  FILE *f;

#ifdef WIN32
  WORD ver = MAKEWORD( 2, 2 );
  WSADATA wsa_data;

  if (WSAStartup(ver, &wsa_data))
    exit(1);

#endif

  e_time = time(NULL);
  e_num_conn = 1;
  e_data_len = 1024;
  e_send_loop = -1;
  e_flood = 0;
  e_data_flood = 0;
  e_threads = 1;
  e_proto = SOCK_STREAM;

  if (argc > 1) {
    k = 1;
    while((opt = getopt(argc, argv,
			"Vh:H:p:P:c:d:l:t:fFA:i:g:a:n:D:Q:L:K:uR:m:T:rq6"))
	  != EOF) {
      switch(opt) {
      case 'V':
        fprintf(stderr,
		"ConnTest, version 1.13 (c) 1999 - 2010 Pekka Riikonen\n");
        usage();
        break;
      case '6':
	e_want_ip6 = 1;
	k++;
        break;
      case 'q':
	e_quiet = 1;
	k++;
        break;
      case 'h':
        k++;
	if (argv[k] == (char *)NULL)
          usage();
        e_host = strdup(argv[k]);
        k++;
        break;
      case 'H':
        k++;
        if (argv[k] == (char *)NULL)
          usage();
	GET_SEPARATED(argv[k], '-', e_ip_start, e_ip_end);
        k++;
        break;
      case 'L':
        k++;
	if (argv[k] == (char *)NULL)
          usage();
        e_lip = strdup(argv[k]);
        k++;
        break;
      case 'R':
        k++;
        if (argv[k] == (char *)NULL)
          usage();
	GET_SEPARATED(argv[k], '-', e_lip_start, e_lip_end);
	e_lip = strdup(e_lip_start);
	e_lip_s = atoi(strrchr(e_lip_start, '.') + 1);
	e_lip_e = atoi(strrchr(e_lip_end, '.') + 1);
        k++;
        break;
      case 'r':
        k++;
        e_random_ip = 1;
	e_lip = strdup("1.2.3.4");
        break;
      case 'p':
        k++;
        if (argv[k] == (char *)NULL)
          usage();
        e_port = atoi(argv[k]);
        k++;
        break;
      case 'K':
        k++;
        if (argv[k] == (char *)NULL)
          usage();
        e_lport = atoi(argv[k]);
        k++;
        break;
      case 'P':
        k++;
        if (argv[k] == (char *)NULL)
          usage();
	if (!strcasecmp(argv[k], "tcp")) {
	  e_proto = SOCK_STREAM;
	  e_sock_type = PF_INET;
	  e_sock_proto = 0;
	} else if (!strcasecmp(argv[k], "udp")) {
	  e_proto = SOCK_DGRAM;
	  e_sock_type = PF_INET;
	  e_sock_proto = 0;
	} else if (!strcasecmp(argv[k], "raw")) {
	  e_proto = SOCK_RAW;
	  e_sock_type = PF_INET;
	  e_sock_proto = IPPROTO_RAW;
	} else if (isdigit(argv[k][0])) {
	  e_proto = SOCK_RAW;
	  e_sock_type = PF_INET;
	  e_sock_proto = atoi(argv[k]);
	}
	else
          usage();
        k++;
        break;
      case 'c':
        k++;
        if (argv[k] == (char *)NULL)
          usage();
        e_num_conn = atoi(argv[k]);
        k++;
        break;
      case 'd':
        k++;
        if (argv[k] == (char *)NULL)
          usage();
        e_data_len = atoi(argv[k]);
        k++;
        break;
      case 'l':
        k++;
        if (argv[k] == (char *)NULL)
          usage();
        e_send_loop = atoi(argv[k]);
        k++;
        break;
      case 't':
        k++;
        if (argv[k] == (char *)NULL)
          usage();
        e_threads = atoi(argv[k]);
        k++;
        break;
      case 'n':
        k++;
        if (argv[k] == (char *)NULL)
          usage();
        e_sleep = atoi(argv[k]);
        k++;
        break;
      case 'f':
        k++;
        e_flood = 1;
        break;
      case 'F':
        k++;
        e_data_flood = 1;
        break;
      case 'u':
        k++;
        e_unique = 1;
        break;
      case 'A':
        k++;
        if (argv[k] == (char *)NULL)
          usage();
	if (!strcasecmp(argv[k], "ike-aggr")) {
	  e_do_ike = 1;
	  e_ike_attack = IKE_ATTACK_AGGR;
        }
	if (!strcasecmp(argv[k], "ike-mm")) {
	  e_do_ike = 1;
	  e_ike_attack = IKE_ATTACK_MM;
        }
        k++;
	break;
      case 'i':
        k++;
        if (argv[k] == (char *)NULL)
          usage();
	e_ike_identity = strdup(argv[k]);
        k++;
	break;
      case 'D':
        k++;
        if (argv[k] == (char *)NULL)
          usage();
	if (strlen(argv[k]) > 2 && argv[k][0] == '0' && argv[k][1] == 'x') {
	  e_header = (char *)hex2data(argv[k] + 2, &e_header_len);
        } else {
	  e_header = strdup(argv[k]);
	  e_header_len = strlen(e_header);
	}
        k++;
	break;
      case 'Q':
        k++;
        if (argv[k] == (char *)NULL)
          usage();
        f = fopen(argv[k], "r");
	if (!f) {
	  fprintf(stderr, "%s\n", strerror(errno));
	  exit(1);
	}
        len = fread(fdata, 1, sizeof(fdata), f);
        fclose(f);
	e_header = memdup(fdata, len);
	e_header_len = len;
        k++;
	break;
      case 'g':
        k++;
        if (argv[k] == (char *)NULL)
          usage();
	e_ike_group = atoi(argv[k]);
        k++;
	break;
      case 'm':
        k++;
        if (argv[k] == (char *)NULL)
          usage();
	e_pmtu = atoi(argv[k]);
        k++;
	break;
      case 'T':
        k++;
        if (argv[k] == (char *)NULL)
          usage();
	e_ttl = atoi(argv[k]);
        k++;
	break;
      case 'a':
        k++;
        if (argv[k] == (char *)NULL)
          usage();
	if (!strcasecmp(argv[k], "psk"))
	  e_ike_auth = 1;
	if (!strcasecmp(argv[k], "dss"))
	  e_ike_auth = 2;
	if (!strcasecmp(argv[k], "rsa"))
	  e_ike_auth = 3;
	if (!strcasecmp(argv[k], "xauth-psk"))
	  e_ike_auth = 65001;
	if (!strcasecmp(argv[k], "xauth-dss"))
	  e_ike_auth = 65003;
	if (!strcasecmp(argv[k], "xauth-rsa"))
	  e_ike_auth = 65005;
        k++;
	break;
      default:
        usage();
        break;
      }
    }
  } else {
    usage();
  }

  /* sanity checks */
  if (e_data_len < 1)
    e_data_len = 1;
  if (e_num_conn < 0)
    e_num_conn = 1;
  if (e_threads < 1)
    e_threads = 1;

  if (e_num_conn > MAX_SOCKETS) {
    fprintf(stderr, "conntest: %d are maximum number of connections\n",
            MAX_SOCKETS);
    exit(1);
  }

  if (e_threads > e_num_conn) {
    fprintf(stderr, "conntest: too many threads (not enough connections)\n");
    exit(1);
  }

  if (e_do_ike) {
    void *ike;
    create_connection(e_port, e_host, 0, &s);
    ike = ike_start();
    ike_add(ike, s.sockets[0], &s.udp_dest[0], e_data_flood, e_ike_identity,
	    e_ike_group, e_ike_auth, e_ike_attack);
    sleep(10);
    exit(1);
  }

  if (e_ip_start && e_ip_end) {
    int start, end, count = 0;
    start = atoi(strrchr(e_ip_start, '.') + 1);
    end = atoi(strrchr(e_ip_end, '.') + 1);

    for (k = start; k <= end; k++) {
      /* create the connections */
      char tmp[64], ip[64];

      memset(ip, 0, sizeof(ip));
      memcpy(tmp, e_ip_start, strlen(e_ip_start));
      *strrchr(tmp, '.') = '\0';
      snprintf(ip, sizeof(ip) - 1, "%s.%d", tmp, k);

      for (i = 0; i < e_num_conn; i++) {
	if (!e_quiet)
	  fprintf(stderr, "#%3d: ", i + 1);
      retry0:
	if (create_connection(e_port, ip, count, &s) < 0) {
	  if (!e_quiet)
	    fprintf(stderr, "Retrying after 30 seconds\n");
	  sleep(30);
	  goto retry0;
	}

	if (!e_flood)
	 usleep(50000);
	count++;
      }
    }
    i = count;
  } else {
    /* create the connections */
    for (i = 0; i < e_num_conn; i++) {
      if (!e_quiet)
	fprintf(stderr, "#%3d: ", i + 1);
    retry:
      if (create_connection(e_port, e_host, i, &s) < 0) {
	if (!e_quiet)
	  fprintf(stderr, "Retrying after 30 seconds\n");
	sleep(30);
	goto retry;
      }

      if (!e_flood)
	usleep(50000);
    }
  }

  s.num_sockets = i;

  /* generate data */
  len = e_data_len;
  data = (char *)malloc(sizeof(char) * len + 1);
  for (i = 0, k = 0; i < len; i++, k++) {
    if (k > 255)
      k = 0;
    data[i] = k + (e_unique ? time(NULL) : 0);
  }

  if (e_header) {
    if (e_proto == SOCK_RAW && (e_lip || e_sock_proto == IPPROTO_RAW)) {
      if (e_data_len - 20 < e_header_len) {
        fprintf(stderr,
		"Data length (-d) is shorter than specified header (-D)\n");
        exit(1);
      }
      memcpy(data + 20, e_header, e_header_len);
    } else {
      if (e_data_len < e_header_len) {
        fprintf(stderr,
		"Data length (-d) is shorter than specified header (-D)\n");
        exit(1);
      }
      memcpy(data, e_header, e_header_len);
    }
  }

  /* do the data sending (if single thread) */
  if (e_threads == 1) {
    if (!e_quiet)
      fprintf(stderr, "Sending data (%d bytes) to connection n:o ", len);
    if (e_send_loop < 0)
      k = -2;
    else
      k = 0;

    while(k < e_send_loop) {
      for (i = 0; i < s.num_sockets; i++) {
	if (!e_quiet) {
	  fprintf(stderr, "%5d\b\b\b\b\b", i + 1);
	  fflush(stderr);
	}

        if ((send_data(&s, i, data, len)) < 0) {
          free(data);
          exit(1);
        }

        if (!e_data_flood) {
	  if (e_sleep * 1000 < 1000000)
            usleep(e_sleep * 1000);
	  else
	    sleep(e_sleep / 1000);
	}
      }
      if (k >= 0)
        k++;
    }
  }
#ifndef WIN32
    else {               /* >1 threads */
    int num, offset;

    /* Generate the threads. Every thread is supposed to have
       equal number of connections (if divides even). */
    offset = 0;
    num = e_num_conn / e_threads;
    for (i = 0; i < e_threads; i++) {
      if (i)
        offset += num;

      if (i == e_threads - 1)
        break;

      if (fork())
        continue;

      /* thread calls */
      thread_data_send(&s, offset, num, e_send_loop, data, len, e_data_flood);
    }

    /* Parent will take care of rest of the connections. */
    if (!e_quiet) {
      fprintf(stderr, "Sending data (%d bytes) to connection n:o ", len);
      fflush(stderr);
    }
    if (e_send_loop < 0)
      k = -2;
    else
      k = 0;

    while(k < e_send_loop) {
      for (i = offset; i < e_num_conn; i++) {
	if (!e_quiet) {
	  fprintf(stderr, "%5d\b\b\b\b\b", i + 1);
	  fflush(stderr);
	}

        if ((send_data(&s, i, data, len)) < 0) {
          free(data);
          exit(1);
        }

        if (!e_data_flood) {
	  if (e_sleep * 1000 < 1000000)
            usleep(e_sleep * 1000);
	  else
	    sleep(e_sleep / 1000);
	}
      }
      if (k >= 0)
        k++;
    }
  }
#endif
  /* close the connections */

  if (!e_quiet)
    fprintf(stderr, "\nClosing connections.\n");

  for (i = 0; i < e_num_conn; i++)
    if ((close_connection(s.sockets[i])) < 0) {
      free(e_header);
      free(data);
      exit(1);
    }

  free(e_header);
  free(data);
  return 0;
}

/* Executing thread. This is the executing child process. */

void thread_data_send(struct sockets *s, int offset, int num,
                      int loop, void *data, int datalen, int flood)
{
  int i, k;
  char buf[256], *cp;

  /* log the connections */
  cp = buf;
  k = sprintf(cp, "PID %d sends data (%d bytes) to connections: ",
              getpid(), datalen);
  cp += k;
  for (i = offset, k = 0; i < num + offset; i++)
    k += sprintf(cp + k, "%d ", i + 1);

  SYSLOG((LOG_INFO, "%s\n", buf));

  e_time = time(NULL) * 2;

  /* do the data sending */
  if (loop < 0)
    k = -2;
  else
    k = 0;

  while(k < loop) {
    for (i = offset; i < num + offset; i++) {
      if ((send_data(s, i, data, datalen)) < 0) {
        SYSLOG((LOG_ERR, "PID %d: Error sending data to connection n:o: %d\n",
               getpid(), i + 1));
        free(data);
        exit(1);
      }

      if (!flood) {
        if (e_sleep * 1000 < 1000000)
          usleep(e_sleep * 1000);
	else
	  sleep(e_sleep / 1000);
      }
    }
    if (k >= 0)
      k++;
  }

  /* close the connections */
  for (i = offset; i < num + offset; i++)
    if ((close_connection(s->sockets[i])) < 0) {
      SYSLOG((LOG_ERR, "PID %d: Error closing connection n:o: %d\n",
             getpid(), i + 1));
      free(data);
      exit(1);
    }

  free(data);
  exit(0);
}
