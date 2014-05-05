/*

  conntest.c

  Copyright (c) 1999 - 2011 Pekka Riikonen, priikone@iki.fi.

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
#include <sys/uio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <syslog.h>
#endif

#include "conntest.h"
#include "ike.h"

/* Ethernet header len */
#define ETHLEN 14

/* IPv4 header len */
#define IP4LEN 20

/* IPv6 header len */
#define IP6LEN 40

/* Data rate units */
#define KBIT 1000
#define KIBIT 1024
#define MBIT 1000000
#define MIBIT 1048576
#define GBIT 1000000000
#define GIBIT 1073741957

char *e_host = NULL;
char *e_ip_start = NULL;
char *e_ip_end = NULL;
char *e_lip = NULL;
char *e_lip_start = NULL;
char *e_lip_end = NULL;
int e_lip_s = 1;
int e_lip_e = 0;
int e_port = 9;
int e_port_end = 9;
int e_lport = 0;
int e_num_conn;
int e_data_len;
int e_send_loop;
int e_flood, e_data_flood;
int e_sleep = 1000;
int e_speed = 0;
int e_speed_unit = 0;
int e_num_pkts = 0;
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
int e_random_lport = 0;
unsigned char e_tcp_flags = 0;
unsigned char e_tos = 0;
int e_pmtu = -1;
int e_ttl = -1;
int e_time;
int e_want_ip6 = 0;
int e_force_ip4 = 0;
int e_quiet = 0;
int e_hexdump = 0;
char *e_ifname = NULL;
unsigned long long e_freq = 0;

static unsigned char ip4_header[20] = "\x45\x00\x00\x00\x00\x00\x00\x00\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";

#define MAX_SOCKETS 40000

struct sockets {
  struct {
    int sock;
    unsigned char iph[20];
    union {
      unsigned char udp[8];
      unsigned char tcp[20];
    };
    c_sockaddr udp_dest;
    c_sockaddr udp_src;
#ifdef MAX_SOCKETS
  } sockets[MAX_SOCKETS];
#else
  } *sockets;
#endif /* MAX_SOCKETS */
  int num_sockets;
};

#define PUT32(d, n)							\
do {									\
  (d)[0] = (n) >> 24 & 0xff;						\
  (d)[1] = (n) >> 16 & 0xff;						\
  (d)[2] = (n) >> 8 & 0xff;						\
  (d)[3] = (n) & 0xff;							\
} while(0)

#define PUT16(d, n)							\
do {									\
  (d)[0] = (n) >> 8 & 0xff;						\
  (d)[1] = (n) & 0xff;							\
} while(0)

#define SWAB32(l) ((unsigned int)					\
   (((unsigned int)(l) & (unsigned int)0x000000FFUL) << 24) |		\
   (((unsigned int)(l) & (unsigned int)0x0000FF00UL) << 8)  |		\
   (((unsigned int)(l) & (unsigned int)0x00FF0000UL) >> 8)  |		\
   (((unsigned int)(l) & (unsigned int)0xFF000000UL) >> 24))

#define SIZEOF_SOCKADDR(so) ((so).sa.sa_family == AF_INET6 ?    \
  sizeof((so).sin6) : sizeof((so).sin))

void sockets_alloc(struct sockets *s, unsigned int num)
{
#ifndef MAX_SOCKETS
  s->sockets = calloc(num , sizeof(*s->sockets));
  if (!s->sockets)
    exit(1);
#endif /* !MAX_SOCKETS */
}

static inline
unsigned long long rdtsc(void)
{
#if defined(__GNUC__) || defined(__ICC)
#if defined(__i386__) || defined(__i486__) || defined(__i586__) || defined(__i686__) || defined(__i786__)
  unsigned long long x;
  asm volatile ("rdtsc" : "=A" (x));
  return x;

#elif defined(__x86_64__)
  unsigned long x;
  unsigned int hi, lo;
  asm volatile ("rdtsc" : "=a" (lo), "=d" (hi));
  x = ((unsigned long)lo | ((unsigned long)hi << 32));
  return x;

#elif defined(__powerpc__)
  unsigned int hi, lo, tmp;
  asm volatile ("0:            \n\t"
                "mftbu   %0    \n\t"
                "mftb    %1    \n\t"
                "mftbu   %2    \n\t"
                "cmpw    %2,%0 \n\t"
                "bne     0b    \n"
                : "=r" (hi), "=r" (lo), "=r" (tmp));
  x = ((unsigned long)lo | ((unsigned long)hi << 32));
  return x;

#else
  return 0;
#endif /* i486 */

#elif defined(WIN32)
  __asm rdtsc

#else
  return 0;
#endif /* __GNUC__ || __ICC */
}

static inline void bsleep(unsigned int t)
{
  unsigned long long end = rdtsc();

  if (!end) {
    usleep(t);
    return;
  }

  end = rdtsc() + ((unsigned long long)t * (e_freq / 1000));
  while (rdtsc() < end) {
#if defined(__GNUC__) || defined(__ICC)
#if defined(__i386__) || defined(__i486__) || defined(__i586__) || defined(__i686__) || defined(__i786__) || defined(__x86_64__)
    asm volatile ("rep; nop" ::: "memory");
#endif
#endif
  }
}

void hexdump(const unsigned char *data, size_t data_len,
             FILE *output)
{
  int i, k;
  int off, pos, count;
  int len = data_len;

  k = 0;
  pos = 0;
  count = 16;
  off = len % 16;
  while (1) {
    if (off) {
      if ((len - pos) < 16 && (len - pos <= len - off))
        count = off;
    } else {
      if (pos == len)
        count = 0;
    }
    if (off == len)
      count = len;

    if (count)
      fprintf(output, "%08X  ", k++ * 16);

    for (i = 0; i < count; i++) {
      fprintf(output, "%02X ", data[pos + i]);

      if ((i + 1) % 4 == 0)
        fprintf(output, " ");
    }

    if (count && count < 16) {
      int j;

      for (j = 0; j < 16 - count; j++) {
        fprintf(output, "   ");

        if ((j + count + 1) % 4 == 0)
          fprintf(output, " ");
      }
    }

    for (i = 0; i < count; i++) {
      char ch;

      if (data[pos] < 32 || data[pos] >= 127)
        ch = '.';
      else
        ch = data[pos];

      fprintf(output, "%c", ch);
      pos++;
    }

    if (count)
      fprintf(output, "\n");

    if (count < 16)
      break;
  }
}

void thread_data_send(struct sockets *s, int offset, int num,
                      int loop, void *data, int datalen, int flood);

int is_ip6(const char *addr)
{
  if (!addr)
    return 0;
  while (*addr && *addr != '%') {
    if (*addr != ':' && !isxdigit((int)*addr))
      return 0;
    addr++;
  }

  return 1;
}

int c_gethostbyname(char *name, int want_ipv6, char *raddr, int addr_size,
		    unsigned char *iphdr, int local, int *family,
		    int port, c_sockaddr *addr)
{
  struct addrinfo hints, *ai, *tmp, *ip4 = NULL, *ip6 = NULL;
  struct hostent *hp;
  c_sockaddr *s;

  if (e_force_ip4) {
    hp = gethostbyname(name);

    memcpy(&addr->sin.sin_addr, hp->h_addr_list[0], sizeof(addr->sin.sin_addr));
    addr->sin.sin_family = AF_INET;
    addr->sin.sin_port = port ? htons(port) : 0;
    *family = AF_INET;

    /* Update raw IP header */
    local = local ? 12 : 16;
    memcpy(iphdr + local, hp->h_addr_list[0], 4);
  } else {
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

    s = (c_sockaddr *)ai->ai_addr;

    if (want_ipv6 && ip6) {
      memcpy((unsigned char *)&addr->sin6.sin6_addr,
	     &s->sin6.sin6_addr, sizeof(s->sin6.sin6_addr));

      addr->sin6.sin6_family = AF_INET6;
      if (e_proto != SOCK_RAW)
        addr->sin6.sin6_port = port ? htons(port) : 0;
      addr->sin6.sin6_scope_id = s->sin6.sin6_scope_id;
      *family = AF_INET6;
    } else {
      memcpy((unsigned char *)&addr->sin.sin_addr.s_addr,
	     &s->sin.sin_addr.s_addr, sizeof(s->sin.sin_addr.s_addr));

      addr->sin.sin_family = AF_INET;
      addr->sin.sin_port = port ? htons(port) : 0;
      *family = AF_INET;

      /* Update raw IP header */
      local = local ? 12 : 16;
      memcpy(iphdr + local, &s->sin.sin_addr.s_addr, 4);
    }

    if (getnameinfo(tmp->ai_addr, tmp->ai_addrlen, raddr,
                    addr_size, NULL, 0, NI_NUMERICHOST)) {
      freeaddrinfo(ai);
      return 0;
    }

    freeaddrinfo(ai);
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
      fprintf(stderr, "setsockopt(): %s (%d %d %d) \n", strerror(errno),
	      t, s, val);
      return -1;
    }
  return 0;
}

int set_sockopt2(int socket, int t, int s, void *optval, int optlen)
{
  if (setsockopt(socket, t, s, optval, optlen) < 0)
    {
      fprintf(stderr, "setsockopt(): %s (%d %p %d) \n", strerror(errno),
	      t, optval, optlen);
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
  char src[64], dst[64];
#ifdef WIN32
  unsigned long addr;
#endif
  unsigned char *iph = sockets->sockets[index].iph;
  unsigned char *udp = sockets->sockets[index].udp;
  unsigned char *tcp = sockets->sockets[index].tcp;
  struct timeval timeo;

  memset(src, 0, sizeof(src));
  memset(dst, 0, sizeof(dst));
  memset(&timeo, 0, sizeof(timeo));

  if (!e_want_ip6)
    memcpy(iph, ip4_header, 20);

  /* If raw protocol was given the caller must provide the IP header (or
     part of it). */
  if (e_sock_proto == IPPROTO_RAW && !e_want_ip6)
    memcpy(iph, e_header, e_header_len < 20 ? e_header_len : 20);

  /* Do host look up */
  if (dhost) {
#ifndef WIN32
    if (!c_gethostbyname(dhost, e_want_ip6, dst, sizeof(dst), iph, 0,
			 &e_sock_type, port, &desthost)) {
      fprintf(stderr, "Network (%s) is unreachable\n", dhost);
      return -1;
    }
    if (!e_force_ip4 && is_ip6(dst))
      e_want_ip6 = 1;
#else
    addr = inet_addr(dhost);
    memcpy(&desthost.sin_addr, &addr, sizeof(desthost.sin_addr));
    PUT32(iph + 16, addr);
#endif
  } else {
    /* Any address */
    memset(&desthost, 0, sizeof(desthost));
    desthost.sin.sin_family = e_sock_type;
    desthost.sin.sin_addr.s_addr = INADDR_ANY;
    if (port)
      desthost.sin.sin_port = htons(port);
  }

  /* create the connection socket */
  sock = socket(e_sock_type, e_proto, e_sock_proto);
  if (sock < 0) {
    fprintf(stderr, "socket(): %s\n", strerror(errno));
    return -1;
  }

#ifdef SO_BINDTODEVICE
  /* Bind to specified interface */
  if (e_ifname)
    setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, e_ifname, strlen(e_ifname));
#endif /* SO_BINDTODEVICE */

#ifdef IP_TOS
  if (e_tos) {
    setsockopt(sock, SOL_IP, IP_TOS, &e_tos, sizeof(e_tos));
    iph[1] = e_tos;
  }
#endif /* IP_TOS */

  /* If raw sockets and local IP is selected or is provided in data, set
     IP_HRDINCL sockopt so we can specify our own IP. */
  if (e_proto == SOCK_RAW && (e_lip || e_sock_proto == IPPROTO_RAW)) {
#ifndef WIN32
    if (!e_want_ip6)
      set_sockopt(sock, IPPROTO_IP, IP_HDRINCL, 1);
#endif
    if (e_sock_proto != IPPROTO_RAW && !e_want_ip6)
      iph[9] = e_sock_proto;
  }

  /* Bind to local IP and port */
  if (e_lip || e_lport) {
#ifndef WIN32
    if (e_lip) {
      if (!c_gethostbyname(e_lip, e_want_ip6, src, sizeof(src), iph, 1,
			   &e_sock_type, e_lport, &srchost)) {
          fprintf(stderr, "Network (%s) is unreachable\n", e_lip);
          return -1;
      }
    } else {
      /* Any address */
      memset(&srchost, 0, sizeof(srchost));
      srchost.sin.sin_family = e_sock_type;
      srchost.sin.sin_addr.s_addr = INADDR_ANY;
      if (e_lport)
        srchost.sin.sin_port = htons(e_lport);
    }
#else
    if (e_lip) {
      addr = inet_addr(e_lip);
      memcpy(&srchost.sin_addr, &addr, sizeof(srchost.sin_addr));
      PUT32(iph + 12, addr);
    }
#endif
    if (e_proto != SOCK_RAW) {
      if (bind(sock, (struct sockaddr *)&srchost, sizeof(srchost))) {
        fprintf(stderr, "Could not bind to %s:%d\n", e_lip, e_lport);
        exit(1);
      }
    }
  }

  /* If user provided header (-D) is not present in raw UDP protocol, let's
     provide valid UDP header. */
  if (e_proto == SOCK_RAW && e_sock_proto == IPPROTO_UDP && !e_want_ip6 &&
      !e_header) {
    if (!srchost.sin.sin_port)
      PUT16(udp, 9);
    else
      memcpy(udp, &srchost.sin.sin_port, 2);
    memcpy(udp + 2, &desthost.sin.sin_port, 2);
    if (e_lip)
      PUT16(udp + 4, e_data_len - 20);
    else
      PUT16(udp + 4, e_data_len);
    PUT16(udp + 6, 0);		/* But no checksum */
  }

  /* If user provided header (-D) is not present in raw TCP protocol, let's
     provide "valid" TCP header. */
  if (e_proto == SOCK_RAW && e_sock_proto == IPPROTO_TCP && !e_want_ip6 &&
      !e_header) {
    if (!srchost.sin.sin_port)
      PUT16(tcp, 9);
    else
      memcpy(tcp, &srchost.sin.sin_port, 2);
    memcpy(tcp + 2, &desthost.sin.sin_port, 2);
    PUT32(tcp + 4, 1);		/* seqno */
    PUT32(tcp + 8, 0);		/* ack */
    tcp[12] = 0x50;		/* length */
    tcp[13] = e_tcp_flags;	/* flags, 8 bits */
    PUT16(tcp + 14, 10000);	/* window size */
    PUT16(tcp + 16, 0);		/* bogus checksum */
    PUT16(tcp + 18, 0);		/* urg */
  }

  /* Set PMTU discovery policy */
#ifndef WIN32
  if (e_pmtu != -1) {
    if (e_want_ip6) {
#ifdef IPV6_MTU_DISCOVER
      set_sockopt(sock, IPPROTO_IPV6, IPV6_MTU_DISCOVER, e_pmtu);
#endif /* IPV6_MTU_DISCOVER */
    } else {
#ifdef IP_MTU_DISCOVER
      set_sockopt(sock, IPPROTO_IP, IP_MTU_DISCOVER, e_pmtu);
#endif /* IP_MTU_DISCOVER */
      if (e_proto == SOCK_RAW && e_pmtu == 3)
        iph[6] = 0x40;
    }
  }

  /* Set TTL */
  if (e_ttl != -1) {
    if (e_ttl)
      set_sockopt(sock, IPPROTO_IP, IP_TTL, e_ttl);
    if (e_proto == SOCK_RAW && !e_want_ip6)
      iph[8] = e_ttl;
  }
#endif

  /* connect to the host */
  if (e_proto == SOCK_STREAM) {
    if (!e_quiet)
      fprintf(stderr, "Connecting to port %d of host %s (%s).", port,
	      dhost ? dhost : "N/A", dhost ? dst : "N/A");

    i = connect(sock, &desthost.sa, SIZEOF_SOCKADDR(desthost));
    if (i < 0) {
      fprintf(stderr, "\nconnect(): %s\n", strerror(errno));
      shutdown(sock, 2);
      close(sock);
    } else {
      if (!e_quiet)
	fprintf(stderr, " Done.\n");
      set_sockopt(sock, IPPROTO_TCP, TCP_NODELAY, 1);
      sockets->sockets[index].sock = sock;
      set_sockopt(sock, SOL_SOCKET, SO_BROADCAST, 1);
#if defined(SO_SNDBUF)
      if (set_sockopt(sock, SOL_SOCKET, SO_SNDBUF, 1000000) < 0)
	set_sockopt(sock, SOL_SOCKET, SO_SNDBUF, 65535);
#endif /* SO_SNDBUF */
#if defined(SO_SNDBUFFORCE)
      if (set_sockopt(sock, SOL_SOCKET, SO_SNDBUFFORCE, 1000000) < 0)
	set_sockopt(sock, SOL_SOCKET, SO_SNDBUFFORCE, 65535);
#endif /* SO_SNDBUFFORCE */
#if defined(SO_SNDTIMEO)
      set_sockopt2(sock, SOL_SOCKET, SO_SNDTIMEO, (void *)&timeo, sizeof(timeo));
#endif /* SO_SNDTIMEO */
      return sock;
    }
  } else {
    if (!e_quiet)
      fprintf(stderr, "Sending data to port %d of host %s (%s).\n", port,
	      dhost ? dhost : "N/A", dhost ? dst : "N/A");
    sockets->sockets[index].sock = sock;
    memcpy(&sockets->sockets[index].udp_dest, &desthost, sizeof(desthost));
    memcpy(&sockets->sockets[index].udp_src, &srchost, sizeof(srchost));
    set_sockopt(sock, SOL_SOCKET, SO_BROADCAST, 1);
#if defined(SO_SNDBUF)
    if (set_sockopt(sock, SOL_SOCKET, SO_SNDBUF, 1000000) < 0)
      set_sockopt(sock, SOL_SOCKET, SO_SNDBUF, 65535);
#endif /* SO_SNDBUF */
#if defined(SO_SNDBUFFORCE)
    if (set_sockopt(sock, SOL_SOCKET, SO_SNDBUFFORCE, 1000000) < 0)
      set_sockopt(sock, SOL_SOCKET, SO_SNDBUFFORCE, 65535);
#endif /* SO_SNDBUFFORCE */
#if defined(SO_SNDTIMEO)
      set_sockopt2(sock, SOL_SOCKET, SO_SNDTIMEO, (void *)&timeo, sizeof(timeo));
#endif /* SO_SNDTIMEO */
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
  int ret, i, off = 0;
  int sock = s->sockets[index].sock;
  unsigned char *iph = s->sockets[index].iph;
  c_sockaddr *udp = &s->sockets[index].udp_dest;
  c_sockaddr *src = &s->sockets[index].udp_src;
  unsigned char *d = data, tmp[40];
  struct msghdr msg;
  struct cmsghdr *cm;
  struct in6_pktinfo *pkt;
  struct iovec iov;

  /* If requested, make data unique */
  if (e_unique)
    for (i = e_header_len; i < (len - e_header_len) - 1; i++)
      d[i] ^= d[i + 1] ^ ((d[i] + 0x9d2c5681UL) * 1812433253UL) >> 11;

  if (e_want_ip6) {
    /* IPv6 */

    /* For raw sockets set up msghdr and use sendmsg() */
    if (e_proto == SOCK_RAW) {
      iov.iov_base = data;
      iov.iov_len = len;

      memset(&msg, 0, sizeof(msg));
      msg.msg_name = (void *)&udp->sa;
      msg.msg_namelen = SIZEOF_SOCKADDR(*udp);
      msg.msg_iov = &iov;
      msg.msg_iovlen = 1;

      msg.msg_control = cm = (struct cmsghdr *)tmp;
      cm->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
      msg.msg_controllen = cm->cmsg_len;
      cm->cmsg_level = IPPROTO_IPV6;
      cm->cmsg_type = IPV6_PKTINFO;

      pkt = (struct in6_pktinfo *)CMSG_DATA(cm);
      pkt->ipi6_ifindex = src->sin6.sin6_scope_id;
      memcpy(&pkt->ipi6_addr, &src->sin6.sin6_addr, 16);
    }
  } else {
    /* IPv4 */

    /* If raw sockets and local IP is specified, now copy the IP header */
    if (e_proto == SOCK_RAW && (e_lip || e_sock_proto == IPPROTO_RAW)) {
      memcpy(d, iph, 20);
      off = 20;
    }

    /* If user provided header is not present in raw UDP/TCP protocol, let's
       provide valid pre-built header. */
    if (e_proto == SOCK_RAW && e_sock_proto == IPPROTO_UDP && !e_header)
      memcpy(d + off, s->sockets[index].udp, 8);
    else if (e_proto == SOCK_RAW && e_sock_proto == IPPROTO_TCP && !e_header)
      memcpy(d + off, s->sockets[index].tcp, 20);

    /* Randomize source port if requested */
    if (e_random_lport) {
      d[off] = d[15] ^= (e_time ^ (e_time >> 11));
      d[off + 1] = d[14] ^= d[13] ^ ((d[12] << 7) & 0x9d2c5680UL);
      e_time += 2749;
    }

    /* Randomize source IP if requested */
    if (e_random_ip) {
      iph[12] = d[12] ^= (e_time ^ (e_time >> 11));
      iph[13] = d[13] ^= d[12] ^ ((d[13] << 7) & 0x9d2c5680UL);
      iph[14] = d[14] ^= d[13] ^ ((d[14] << 15) & 0xefc60000UL);
      iph[15] = d[15] ^= d[14] ^ (d[15] >> 18);
      if (d[12] == 0 || d[12] == 224 || d[12] == 255)
        iph[12] = d[12] = 1;
      if (d[15] == 255)
        iph[15] = d[15] = 1;
      e_time += 2749;
    }

    /* Source IP range if requested */
    if (e_lip_start && e_lip_end) {
      if (e_lip_s > e_lip_e)
        e_lip_s = atoi(strrchr(e_lip_start, '.') + 1);
      iph[15] = d[15] = e_lip_s++;
    }
  }

  if (e_hexdump) {
    fprintf(stdout, "\n");
    hexdump(data, len, stdout);
  }

  if (e_proto == SOCK_STREAM) {
    ret = send(sock, data, len, 0);
    if (ret < 0) {
      fprintf(stderr, "send(sock:%d %d): %s (%d) (pid %d)\n", sock, index,
	      strerror(errno), errno, getpid());
      return -1;
    }
  } else if (e_proto == SOCK_RAW && e_want_ip6) {
    ret = sendmsg(sock, &msg, 0);
    if (ret < 0) {
      fprintf(stderr, "sendmsg(sock:%d %d): %s (%d) (pid %d)\n", sock, index,
	      strerror(errno), errno, getpid());
      return -1;
    }
  } else {
    ret = sendto(sock, data, len, 0, &udp->sa, SIZEOF_SOCKADDR(*udp));
    if (ret < 0) {
      fprintf(stderr, "sendto(sock:%d %d): %s (%d) (pid %d)\n", sock, index,
	      strerror(errno), errno, getpid());
      return -1;
    }
  }

  return 0;
}

void usage()
{
  printf("Usage: conntest OPTIONS\n");
  printf("Options:\n");
  printf(" -h <hostname>    Destination IP or host name\n");
  printf(" -H <IP-IP>       Destination IP range (eg. 10.2.1.1-10.2.1.254)\n");
  printf(" -p <num>[-<num>] Destination port, or port range\n");
  printf(" -L <IP>          Local IP to use if possible (default: auto)\n");
  printf(" -R <IP-IP>       Local IP range when -P is 'raw' or integer value (ipv4)\n");
  printf(" -r               Use random source IP when -P is 'raw' or integer value (ipv4)\n");
  printf(" -b               Use random source port when -P is 'raw' or integer value (ipv4)\n");
  printf(" -B               TCP flags bitmask (8 bits), -P is 6 for TCP (ipv4)\n");
  printf(" -K <port>        Local port to use if possible (default: auto)\n");
  printf(" -P <protocol>    Protocol, 'tcp', 'udp', 'raw' or integer value\n");
  printf(" -c <number>      Number of connections (default: 1)\n");
  printf(" -d <length>      Length of data to transmit, bytes (default: 1024)\n");
  printf(" -D <string>      Data header to packet, if starts with 0x string must be HEX\n");
  printf(" -Q <file>        Data from file, if -P is 'raw' data must include IP header\n");
  printf(" -l <number>      Number of loops to send data (default: infinity)\n");
  printf(" -t <number>      Number of threads used in data sending (default: single)\n");
  printf(" -n <msec>        Data send interval (ignored with -F) (default: 1000 msec)\n");
  printf(" -s <speed><unit> Rate/sec, Units: SI: kbit, Mbit, Gbit, IEC-27: Kib, Mib, Gib\n");
  printf(" -m <pmtu>        PMTU discovery: 0 no PMTU, 2 do PMTU, 3 set DF, ignore PMTU\n");
  printf(" -T <ttl>         Set TTL, 0-255, can be used with raw protocols as well\n");
  printf(" -C <dscp-ecn>    Set DSCP and/or ECN (ECN only with -P 'raw' or integer)\n");
  printf(" -I <ifname>      Bind to specified interface, eg. eth0\n");
  printf(" -u               Each packet will have unique data payload\n");
  printf(" -f               Flood, no delays creating connections (default: undefined)\n");
  printf(" -F               Flood, no delays between data sends (default: undefined)\n");
  printf(" -q               Quiet, don't display anything\n");
  printf(" -6               Use/prefer IPv6 addresses\n");
  printf(" -4               Force IPv4 (no IPv6 support)\n");
  printf(" -x               Hexdump the data to be sent to stdout\n");
  printf(" -V               Display version and help, then exit\n");
  printf("\n  Protocols:\n");
  printf(" -A <protocol>    Do <protocol> attack\n");
  printf("    ike-aggr      IKE Diffie-Hellman attack with aggressive mode\n");
  printf("    ike-mm        IKE Main Mode double packet attack\n");
  printf("    -i <ip>       Aggressive mode identity (default: 0.0.0.0) (ike-aggr only)\n");
  printf("    -g <group>    IKE group (default: 2)\n");
  printf("    -a <auth>     Auth method (psk, rsa, dss, xauth-psk, xauth-rsa, xauth-dss)\n");
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

static inline int frame_size(int data_len)
{
  /* Ethernet + IP header */
  data_len += (ETHLEN + (e_want_ip6 ? IP6LEN : IP4LEN));

  /* UDP header */
  if (e_proto == SOCK_DGRAM)
    data_len += 8;

  /* TCP header */
  if (e_proto == SOCK_STREAM)
    data_len += 20;

  return data_len * 8;
}

static inline int speed_adjust(int speed, int len, unsigned long long c,
			       unsigned long long count)
{
  double tmp;

  /* Adjust sleep interval 10 times per second, spread evenly among all
     threads. */
  tmp = (double)frame_size(len) * ((double)c / (double)count);
  tmp = tmp / (double)(((e_speed * e_speed_unit) / (double)10) / e_threads);
  if (tmp < 0.99f || tmp > 1.01f) {
    tmp = (double)speed * tmp;
    speed = tmp + 0.5f;
    if (speed < 1)
      speed = 1;
  }

  return speed;
}

static int speed_per_usec(int data_len)
{
  double s;
  unsigned long long v;

  if (!e_speed)
    return -1;

  v = rdtsc();
  if (!v) {
    fprintf(stderr, "conntest: rdtsc not available on this platform, -s option is ignored\n");
    return -1;
  }
  usleep(100000);
  v = rdtsc() - v;
  v *= 10;
  e_freq = v / 1000; /* ms */

  data_len = frame_size(data_len);

  s = e_speed * e_speed_unit;
  s /= (double)data_len;

  if (!s)
    s = 1;

  s = 1000000 / s;
  e_num_pkts = 1;

  /* Minimum sleep time of ~1ms */
  if (s < 1000) {
    if (s)
      s = 1000 / s;
    else
      s = 1000;
    data_len *= s;
    e_num_pkts = s + 0.5f;
    s = e_speed * e_speed_unit;
    s /= (double)data_len;

    if (!s)
      s = 1;

    s = 1000000 / s;
  }

  if (e_num_pkts > e_threads)
    e_num_pkts = (e_num_pkts + e_threads - 1) / e_threads;
  else if (e_threads > 1) {
    fprintf(stderr, "conntest: Fallback to 1 thread with selected speed\n");
    e_threads = 1;
  }

  return s;
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
      (ret2) = memdup((x) + _len + 1, strlen((x) + _len + 1));		\
    }									\
} while(0)

int main(int argc, char **argv)
{
  int i, k, l, count = 0, speed;
  char *data, opt;
  unsigned long long v, vtot = 0, c = 0;
  int len, cpkts;
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
			"Vh:H:p:P:c:d:l:t:fFA:i:g:a:n:s:D:Q:L:K:uR:m:T:rq64xI:bB:C:"))
	  != EOF) {
      switch(opt) {
      case 'V':
        fprintf(stderr,
		"ConnTest, version 1.24 (c) 1999 - 2012 Pekka Riikonen\n");
	exit(0);
        break;
      case '6':
	e_want_ip6 = 1;
	k++;
        break;
      case '4':
	e_force_ip4 = 1;
	e_want_ip6 = 0;
	k++;
        break;
      case 'x':
	e_hexdump = 1;
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
      case 'b':
        k++;
        e_random_lport = 1;
        break;
      case 'B':
        k++;
        if (argv[k] == (char *)NULL)
          usage();
        e_tcp_flags = (unsigned char)atoi(argv[k]);
        k++;
        break;
      case 'p':
        k++;
        if (argv[k] == (char *)NULL)
          usage();
	if (strchr(argv[k], '-')) {
	  char *ps = NULL, *pe = NULL;
	  GET_SEPARATED(argv[k], '-', ps, pe);
	  e_port = atoi(ps);
	  e_port_end = atoi(pe);
	  if (!e_port)
	    e_port = 1;
	  if (e_port_end > 0xffff)
	    e_port_end = 0xffff;
        } else {
	  e_port = e_port_end = atoi(argv[k]);
        }
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
      case 's':
	{
	  char *sp = NULL, *stmp = NULL;
          k++;
          if (argv[k] == (char *)NULL)
            usage();
	  if (strstr(argv[k], "kbit")) {
	    GET_SEPARATED(argv[k], 'k', sp, stmp);
	    e_speed = atoi(sp);
	    e_speed_unit = KBIT;
	  } else if (strstr(argv[k], "Kib")) {
	    GET_SEPARATED(argv[k], 'K', sp, stmp);
	    e_speed = atoi(sp);
	    e_speed_unit = KIBIT;
	  } else if (strstr(argv[k], "Mbit")) {
	    GET_SEPARATED(argv[k], 'M', sp, stmp);
	    e_speed = atoi(sp);
	    e_speed_unit = MBIT;
	  } else if (strstr(argv[k], "Mib")) {
	    GET_SEPARATED(argv[k], 'M', sp, stmp);
	    e_speed = atoi(sp);
	    e_speed_unit = MIBIT;
	  } else if (strstr(argv[k], "Gbit")) {
	    GET_SEPARATED(argv[k], 'G', sp, stmp);
	    e_speed = atoi(sp);
	    e_speed_unit = GBIT;
	  } else if (strstr(argv[k], "Gib")) {
	    GET_SEPARATED(argv[k], 'G', sp, stmp);
	    e_speed = atoi(sp);
	    e_speed_unit = GIBIT;
	  } else {
	    fprintf(stderr, "conntest: unsupported rate/sec unit\n");
	    usage();
	  }
	  free(sp);
	  free(stmp);
          k++;
	}
        break;
      case 'I':
        k++;
        if (argv[k] == (char *)NULL)
          usage();
        e_ifname = strdup(argv[k]);
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
      case 'C':
        k++;
        if (argv[k] == (char *)NULL)
          usage();
	e_tos = (unsigned char)atoi(argv[k]);
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

  if (e_threads > e_num_conn) {
    fprintf(stderr, "conntest: too many threads (not enough connections)\n");
    exit(1);
  }

  if (e_do_ike) {
    void *ike;
    create_connection(e_port, e_host, 0, &s);
    ike = ike_start();
    ike_add(ike, s.sockets[0].sock, &s.sockets[0].udp_dest, e_data_flood, e_ike_identity,
	    e_ike_group, e_ike_auth, e_ike_attack);
    sleep(10);
    exit(1);
  }

  if (e_ip_start && e_ip_end) {
    int start, end;
    char *scope = NULL;

    if (!e_force_ip4 && is_ip6(e_ip_start))
      e_want_ip6 = 1;

    if (e_want_ip6) {
      if (strchr(e_ip_start, '%')) {
        scope = strdup(strchr(e_ip_start, '%'));
        *strchr(e_ip_start, '%') = '\0';
        if (strchr(e_ip_end, '%'))
          *strchr(e_ip_end, '%') = '\0';
      }
      start = strtol(strrchr(e_ip_start, ':') + 1, (char **)NULL, 16);
      end = strtol(strrchr(e_ip_end, ':') + 1, (char **)NULL, 16);
    } else {
      start = atoi(strrchr(e_ip_start, '.') + 1);
      end = atoi(strrchr(e_ip_end, '.') + 1);
    }

#ifndef MAX_SOCKETS
    /* Allocate sockets */
    for (k = start; k <= end; k++)
      for (l = e_port; l <= e_port_end; l++)
        for (i = 0; i < e_num_conn; i++)
	  count++;
    sockets_alloc(&s, count);
#endif /* !MAX_SOCKETS */

    count = 0;
    for (k = start; k <= end; k++) {
      /* create the connections */
      char tmp[128], ip[128];

      memset(ip, 0, sizeof(ip));
      memcpy(tmp, e_ip_start, strlen(e_ip_start));
      if (e_want_ip6) {
        *strrchr(tmp, ':') = '\0';
        snprintf(ip, sizeof(ip) - 1, "%s:%x%s", tmp, k, scope ? scope : "");
      } else {
        *strrchr(tmp, '.') = '\0';
        snprintf(ip, sizeof(ip) - 1, "%s.%d", tmp, k);
      }

      for (l = e_port; l <= e_port_end; l++) {
        for (i = 0; i < e_num_conn; i++) {
	  if (!e_quiet)
	    fprintf(stderr, "#%3d: ", i + 1);
        retry0:
	  if (create_connection(l, ip, count, &s) < 0) {
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
    }
    i = count;
  } else {
#ifndef MAX_SOCKETS
    /* Allocate sockets */
    for (l = e_port; l <= e_port_end; l++)
      for (i = 0; i < e_num_conn; i++)
	count++;
    sockets_alloc(&s, count);
#endif /* !MAX_SOCKETS */
    count = 0;

    if (!e_force_ip4 && is_ip6(e_host))
      e_want_ip6 = 1;

    /* create the connections */
    for (l = e_port; l <= e_port_end; l++) {
      for (i = 0; i < e_num_conn; i++) {
        if (!e_quiet)
	  fprintf(stderr, "#%3d: ", i + 1);
      retry:
        if (create_connection(l, e_host, count, &s) < 0) {
	  if (!e_quiet)
	    fprintf(stderr, "Retrying after 30 seconds\n");
	  sleep(30);
	  goto retry;
        }

        if (!e_flood)
	  usleep(50000);
	count++;
      }
    }
    i = count;
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
      if (e_want_ip6)
        memcpy(data, e_header, e_header_len);
      else
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

  speed = speed_per_usec(len);
  cpkts = e_num_pkts;

  /* do the data sending (if single thread) */
  if (e_threads == 1) {
    if (!e_quiet)
      fprintf(stderr, "Sending data (%d bytes) to connection n:o ", len);
    if (e_send_loop < 0)
      k = -2;
    else
      k = 0;

    c = count = 0;
    while(k < e_send_loop) {
      for (i = 0; i < s.num_sockets; i++) {
        v = rdtsc();

	if (!e_quiet) {
	  fprintf(stderr, "%5d\b\b\b\b\b", i + 1);
	  fflush(stderr);
	}

        if ((send_data(&s, i, data, len)) < 0) {
          free(data);
          exit(1);
        }

        if (!e_data_flood) {
	  if (speed != -1) {
            if (--cpkts == 0) {
	      bsleep(speed);
	      cpkts = e_num_pkts;
	    }

	    c++;
	    vtot += rdtsc() - v;
	    if ((double)vtot / (double)e_freq >= 100) {
	      vtot = 0;
	      count++;
	      speed = speed_adjust(speed, len, c, count);
	    }
	  } else if (e_sleep * 1000 < 1000000)
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
    if (e_num_conn < s.num_sockets)
      num = s.num_sockets / e_threads;
    else
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

    c = count = 0;
    num = num + offset > s.num_sockets ? s.num_sockets : num + offset;
    while(k < e_send_loop) {
      for (i = offset; i < num; i++) {
        v = rdtsc();

	if (!e_quiet) {
	  fprintf(stderr, "%5d\b\b\b\b\b", i + 1);
	  fflush(stderr);
	}

        if ((send_data(&s, i, data, len)) < 0) {
          free(data);
          exit(1);
        }

        if (!e_data_flood) {
	  if (speed != -1) {
            if (--cpkts == 0) {
	      bsleep(speed);
	      cpkts = e_num_pkts;
	    }

	    c++;
	    vtot += rdtsc() - v;
	    if ((double)vtot / (double)e_freq >= 100) {
	      vtot = 0;
	      count++;
	      speed = speed_adjust(speed, len, c, count);
	    }
	  } else if (e_sleep * 1000 < 1000000)
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
    if ((close_connection(s.sockets[i].sock)) < 0) {
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
  int i, k, cpkts = e_num_pkts, count = 0, speed;
  unsigned long long v, vtot = 0, c;
  char buf[256];

  /* log the connections */
  num = num + offset > s->num_sockets ? s->num_sockets : num + offset;
  sprintf(buf, "PID %d sends data (%d bytes) to %d connections",
              getpid(), datalen, num);
  SYSLOG((LOG_INFO, "%s\n", buf));

  e_time = time(NULL) * 2;

  /* do the data sending */
  if (loop < 0)
    k = -2;
  else
    k = 0;

  c = count = 0;
  speed = e_speed != -1 ? 1000 : -1;

  while(k < loop) {
    for (i = offset; i < num; i++) {
      v = rdtsc();

      if ((send_data(s, i, data, datalen)) < 0) {
        SYSLOG((LOG_ERR, "PID %d: Error sending data to connection n:o: %d\n",
               getpid(), i + 1));
        free(data);
        exit(1);
      }

      if (!flood) {
	if (e_speed != -1) {
          if (--cpkts == 0) {
	    bsleep(speed);
	    cpkts = e_num_pkts;
	  }

	  c++;
	  vtot += rdtsc() - v;
	  if ((double)vtot / (double)e_freq >= 100) {
	    vtot = 0;
	    count++;
	    speed = speed_adjust(speed, datalen, c, count);
	  }
	} else if (e_sleep * 1000 < 1000000)
          usleep(e_sleep * 1000);
	else
	  sleep(e_sleep / 1000);
      }
    }
    if (k >= 0)
      k++;
  }

  /* close the connections */
  for (i = offset; i < num; i++)
    if ((close_connection(s->sockets[i].sock)) < 0) {
      SYSLOG((LOG_ERR, "PID %d: Error closing connection n:o: %d\n",
             getpid(), i + 1));
      free(data);
      exit(1);
    }

  free(data);
  exit(0);
}
