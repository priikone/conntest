/*

  conntest.c 

  Copyright (c) 1999, 2001 Pekka Riikonen, priikone@silcnet.org.

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

#define MAX_SOCKETS 20000

static char ip4_header[20] = "\x45\x00\x00\x00\x00\x00\x00\x00\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";

struct sockets {
  int sockets[MAX_SOCKETS];
  char ip4h[MAX_SOCKETS][20];
  struct sockaddr_in udp_dest[MAX_SOCKETS];
  int num_sockets;
};

#define PUT32(d, n) (d)[0] = n >> 24 & 0xff; (d)[1] = n >> 16 & 0xff; (d)[2] = n >> 8 & 0xff; (d)[3] = n & 0xff;

void thread_data_send(struct sockets *s, int offset, int num, 
                      int loop, void *data, int datalen, int flood);

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
void set_sockopt(int socket, int t, int s, int val)
{
  int option = val;
  if (setsockopt(socket, t, s,
                 (void *) &option,
                 sizeof(int)) < 0)
    {
      fprintf(stderr, "setsockopt(): %s\n", strerror(errno));
      exit(1);
    }
}

/* Creates a new TCP/IP or UDP/IP connection. Returns the newly created
   socket or -1 on error. */

int create_connection(int port, char *dhost, int index,
		      struct sockets *sockets)
{
  int i, sock;
  struct hostent *hp;
  struct sockaddr_in desthost, srchost;
#ifdef WIN32
  unsigned long addr;
#endif
  char *ip4h = sockets->ip4h[index];

  memcpy(ip4h, ip4_header, 20);

  /* If raw protocol was given the caller must provide the IP header (or
     part of it). */
  if (e_sock_proto == IPPROTO_RAW)
    memcpy(ip4h, e_header, e_header_len < 20 ? e_header_len : 20);

  /* do host look up */
  memset(&desthost, 0, sizeof(desthost));
  desthost.sin_port = htons(port);
  desthost.sin_family = e_sock_type;
  if (dhost) {
#ifndef WIN32
    hp = gethostbyname(dhost);
    if (!hp) {
      fprintf(stderr, "Network (%s) is unreachable\n", dhost);
      return -1;
    }
    /* set socket infos */
    memcpy(&desthost.sin_addr, hp->h_addr_list[0], sizeof(desthost.sin_addr));
    memcpy(ip4h + 16, hp->h_addr_list[0], 4);
#else
    addr = inet_addr(dhost);
    memcpy(&desthost.sin_addr, &addr, sizeof(desthost.sin_addr));
    PUT32(ip4h + 16, addr);
#endif
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
    memset(&srchost, 0, sizeof(srchost));
    srchost.sin_family = e_sock_type;
    srchost.sin_port = htons(e_lport);
#ifndef WIN32
    if (e_lip) {
      hp = gethostbyname(e_lip);
      if (!hp) {
        fprintf(stderr, "Network (%s) is unreachable\n", e_lip);
        return -1;
      }
      memcpy(&srchost.sin_addr, hp->h_addr_list[0], sizeof(srchost.sin_addr));
      memcpy(ip4h + 12, hp->h_addr_list[0], 4);
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
    fprintf(stderr, "Connecting to port %d of host %s (%s).", port,
	    dhost ? dhost : "N/A",
	    dhost ? inet_ntoa(desthost.sin_addr) : "N/A");

    i = connect(sock, (struct sockaddr *)&desthost, sizeof(desthost));
    if (i < 0) {
      fprintf(stderr, "connect(): %s\n", strerror(errno));
      shutdown(sock, 2);
      close(sock);
    } else {
      fprintf(stderr, " Done.\n");
      set_sockopt(sock, IPPROTO_TCP, TCP_NODELAY, 1);
      sockets->sockets[index] = sock;
      set_sockopt(sock, SOL_SOCKET, SO_BROADCAST, 1);
      return sock;
    }
  } else {
    fprintf(stderr, "Sending data to port %d of host %s (%s).\n", port,
	    dhost ? dhost : "N/A",
	    dhost ? inet_ntoa(desthost.sin_addr) : "N/A");
    sockets->sockets[index] = sock;
    memcpy(&sockets->udp_dest[index], &desthost, sizeof(desthost));
    set_sockopt(sock, SOL_SOCKET, SO_BROADCAST, 1);
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
  char *ip4h = s->ip4h[index];
  struct sockaddr_in *udp = &s->udp_dest[index];
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
    ip4h[12] = d[12] ^= (time(NULL) + ((d[15] + 0x9d2c5681L) * 1812433253UL)) >> 11;
    ip4h[13] = d[13] ^= d[12] ^ ((d[14] + 0x9d2c5689L) * 1812433253UL) >> 30;
    ip4h[14] = d[14] ^= d[13] ^ ((d[13] + 0x7d2c5687L) * 1812433253UL) >> 7;
    ip4h[15] = d[15] ^= d[14] ^ ((d[12] + 0x3d2c5683L) * 1812433253UL) >> 11;
    if (d[12] == 0)
      ip4h[12] = d[12] = 1;
    if (d[15] == 255)
      ip4h[15] = d[15] = 1;
  }

  /* Source IP range if requested */
  if (e_lip_start && e_lip_end) {
    if (e_lip_s > e_lip_e)
      e_lip_s = 1;
    ip4h[15] = d[15] = e_lip_s++;
  }

  if (e_proto == SOCK_STREAM) {
    ret = send(sock, data, len, 0);
    if (ret < 0) {
      fprintf(stderr, "send(): %s\n", strerror(errno));
      return -1;
    }
  } else {
    ret = sendto(sock, data, len, 0, (struct sockaddr *)udp, sizeof(*udp));
    if (ret < 0) {
      fprintf(stderr, "sendto(): %s\n", strerror(errno));
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

  e_num_conn = 1;
  e_data_len = 1024;
  e_send_loop = -1;
  e_flood = 0;
  e_data_flood = 0;
  e_threads = 1;
  e_proto = SOCK_STREAM;

  if (argc > 1) {
    k = 1;
    while((opt = getopt(argc, argv, "Vh:H:p:P:c:d:l:t:fFA:i:g:a:n:D:Q:L:K:uR:m:T:r")) != EOF) {
      switch(opt) {
      case 'V':
        fprintf(stderr, "ConnTest, version 1.11 (c) 1999, 2001, 2002, 2006, 2007, 2008 Pekka Riikonen\n");
        usage();
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
	fprintf(stderr, "#%3d: ", i + 1);
      retry0:
	if (create_connection(e_port, ip, count, &s) < 0) {
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
      fprintf(stderr, "#%3d: ", i + 1);
    retry:
      if (create_connection(e_port, e_host, i, &s) < 0) {
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
        fprintf(stderr, "Data length (-d) is shorter than specified header (-D)\n");
        exit(1);
      }
      memcpy(data + 20, e_header, e_header_len);
    } else {
      if (e_data_len < e_header_len) {
        fprintf(stderr, "Data length (-d) is shorter than specified header (-D)\n");
        exit(1);
      }
      memcpy(data, e_header, e_header_len);
    }
  }

  /* do the data sending (if single thread) */
  if (e_threads == 1) {
    fprintf(stderr, "Sending data (%d bytes) to connection n:o ", len);
    if (e_send_loop < 0)
      k = -2;
    else
      k = 0;

    while(k < e_send_loop) {
      for (i = 0; i < s.num_sockets; i++) {
        fprintf(stderr, "%5d\b\b\b\b\b", i + 1);
        fflush(stderr);
        
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
    fprintf(stderr, "Sending data (%d bytes) to connection n:o ", len);
    fflush(stderr);
    if (e_send_loop < 0)
      k = -2;
    else
      k = 0;

    while(k < e_send_loop) {
      for (i = offset; i < e_num_conn; i++) {
        fprintf(stderr, "%5d\b\b\b\b\b", i + 1);
        fflush(stderr);
        
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
