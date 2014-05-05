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
#include <unistd.h>
#include <errno.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <string.h>
#include <syslog.h>

#include "ike.h"

char *e_host;
char *e_ip_start = NULL;
char *e_ip_end = NULL;
int e_port;
int e_num_conn;
int e_data_len;
int e_send_loop;
int e_flood, e_data_flood;
int e_threads;
int e_proto;
int e_do_ike = 0;
char *e_ike_identity = NULL;
int e_ike_group = 2;
int e_ike_auth = 1;

#define MAX_SOCKETS 20000

struct sockets {
  int sockets[MAX_SOCKETS];
  struct sockaddr_in udp_dest[MAX_SOCKETS];
  int num_sockets;
};

void thread_data_send(struct sockets *s, int offset, int num, 
                      int loop, void *data, int datalen, int flood);

/* Creates a new TCP/IP or UDP/IP connection. Returns the newly created
   socket or -1 on error. */

int create_connection(int port, char *dhost, int index,
		      struct sockets *sockets)
{
  int i, sock;
  struct hostent *hp;
  struct sockaddr_in desthost;

  /* do host look up */
  hp = gethostbyname(dhost);
  if (!hp) {
    fprintf(stderr, "Network (%s) is unreachable\n", dhost);
    return -1;
  }

  /* set socket infos */
  memset(&desthost, 0, sizeof(desthost));
  desthost.sin_port = htons(port);
  desthost.sin_family = AF_INET;
  memcpy(&desthost.sin_addr, hp->h_addr_list[0], sizeof(desthost.sin_addr));

  /* create the connection socket */
  sock = socket(AF_INET, e_proto, 0);
  if (sock < 0) {
    fprintf(stderr, "socket(): %s\n", strerror(errno));
    return -1;
  }

  /* connect to the host */
  if (e_proto == SOCK_STREAM) {
    fprintf(stderr, "Connecting to port %d of host %s (%s).", port,
	    dhost, inet_ntoa(desthost.sin_addr));

    i = connect(sock, (struct sockaddr *)&desthost, sizeof(desthost));
    if (i < 0) {
      fprintf(stderr, "connect(): %s\n", strerror(errno));
      shutdown(sock, 2);
      close(sock);
    } else {
      fprintf(stderr, " Done.\n");
      setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (void *)1, 1);
      sockets->sockets[index] = sock;
      return sock;
    }
  } else {
    fprintf(stderr, "Sending data to port %d of host %s (%s).\n", port,
	    dhost, inet_ntoa(desthost.sin_addr));
    sockets->sockets[index] = sock;
    memcpy(&sockets->udp_dest[index], &desthost, sizeof(desthost));
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

int send_data(int sock, struct sockaddr_in *udp, void *data, unsigned int len)
{
  int ret;

  if (e_proto == SOCK_STREAM) {
    ret = send(sock, data, len, 0);
    if (ret < 0) {
      fprintf(stderr, "%s\n", strerror(errno));
      return -1;
    }
  } else {
    ret = sendto(sock, data, len, 0, (struct sockaddr *)udp, sizeof(*udp));
    if (ret < 0) {
      fprintf(stderr, "%s\n", strerror(errno));
      return -1;
    }
  }
    
  return 0;
}

void usage() 
{
  printf("Usage: conntest [-hVhpcdltfF]\n");
  printf("Options:\n");
  printf("  -h <hostname>   destination host name (default: localhost)\n");
  printf("  -H <IP-IP>      IP range (eg. 10.2.1.1-10.2.1.254)\n");
  printf("  -p <port>       destination port (default: 9 (discard))\n");
  printf("  -P <protocol>   protocol (default: tcp)\n");
  printf("  -c <number>     number of connections (default: 10)\n");
  printf("  -d <length>     length of data to transmit (default: 1024)\n");
  printf("  -l <number>     number of loops to send data (default: infinity)\n");
  printf("  -t <number>     number of threads used in data sending (default: single)\n");
  printf("  -f              flood, no delays creating connections (default: undefined)\n");
  printf("  -F              flood, no delays between data sends (default: undefined)\n");
  printf("  -V              display version and help\n");
  printf("\n  Protocols:\n");
  printf("  -A <protocol>   Do <protocol> attack\n");
  printf("     ike          IKE Diffie-Hellman attack with aggressive mode\n");
  printf("     -i <ip>      Aggressive mode identity (default: 0.0.0.0)\n");
  printf("     -g <group>   IKE group (default: 2)\n");
  printf("     -a <auth>    IKE authentication method (psk or sig)\n");

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

  e_host = "localhost";
  e_port = 9;
  e_num_conn = 10;
  e_data_len = 1024;
  e_send_loop = -1;
  e_flood = 0;
  e_data_flood = 0;
  e_threads = 1;
  e_proto = SOCK_STREAM;

  if (argc > 1) {
    k = 1;
    while((opt = getopt(argc, argv, "Vh:H:p:P:c:d:l:t:fFA:i:g:a:")) != EOF) {
      switch(opt) {
      case 'V':
        fprintf(stderr, "ConnTest, version 1.6 (c) 1999, 2001 Pekka Riikonen\n");
        usage();
        break;
      case 'h':
        k++;
        if (argv[k] == (char *)NULL)
          usage();
        e_host = argv[k];
        k++;
        break;
      case 'H':
        k++;
        if (argv[k] == (char *)NULL)
          usage();
	GET_SEPARATED(argv[k], '-', e_ip_start, e_ip_end);
        k++;
        break;
      case 'p':
        k++;
        if (argv[k] == (char *)NULL)
          usage();
        e_port = atoi(argv[k]);
        k++;
        break;
      case 'P':
        k++;
        if (argv[k] == (char *)NULL)
          usage();
	if (!strcasecmp(argv[k], "tcp"))
	  e_proto = SOCK_STREAM;
	else if (!strcasecmp(argv[k], "udp"))
	  e_proto = SOCK_DGRAM;
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
      case 'f':
        k++;
        e_flood = 1;
        break;
      case 'F':
        k++;
        e_data_flood = 1;
        break;
      case 'A':
        k++;
        if (argv[k] == (char *)NULL)
          usage();
	if (!strcasecmp(argv[k], "ike"))
	  e_do_ike = 1;
        k++;
	break;
      case 'i':
        k++;
        if (argv[k] == (char *)NULL)
          usage();
	e_ike_identity = strdup(argv[k]);
        k++;
	break;
      case 'g':
        k++;
        if (argv[k] == (char *)NULL)
          usage();
	e_ike_group = atoi(argv[k]);
        k++;
	break;
      case 'a':
        k++;
        if (argv[k] == (char *)NULL)
          usage();
	if (!strcasecmp(argv[k], "psk"))
	  e_ike_auth = 1;
	if (!strcasecmp(argv[k], "sig"))
	  e_ike_auth = 3;
        k++;
	break;
      default:
        usage();
        break;
      }
    }
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
	    e_ike_group, e_ike_auth);
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
	  fprintf(stderr, "Retrying after 60 seconds\n");
	  sleep(60);
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
	fprintf(stderr, "Retrying after 60 seconds\n");
	sleep(60);
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
    data[i] = k;
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
        
        if ((send_data(s.sockets[i], &s.udp_dest[i], data, len)) < 0) {
          free(data);
          exit(1);
        }
        
        if (!e_data_flood)
          sleep(1);
      }
      if (k >= 0)
        k++;
    }
  } else {               /* >1 threads */
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
        
        if ((send_data(s.sockets[i], &s.udp_dest[i], data, len)) < 0) {
          free(data);
          exit(1);
        }
        
        if (!e_data_flood)
          sleep(1);
      }
      if (k >= 0)
        k++;
    }
  }

  /* close the connections */

  fprintf(stderr, "\nClosing connections.\n");

  for (i = 0; i < e_num_conn; i++)
    if ((close_connection(s.sockets[i])) < 0) {
      free(data);
      exit(1);
    }

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
  syslog(LOG_INFO, "%s\n", buf);

  /* do the data sending */
  if (loop < 0)
    k = -2;
  else
    k = 0;
  
  while(k < loop) {
    for (i = offset; i < num + offset; i++) {
      if ((send_data(s->sockets[i], &s->udp_dest[i], data, datalen)) < 0) {
        syslog(LOG_ERR, "PID %d: Error sending data to connection n:o: %d\n", 
               getpid(), i + 1);
        free(data);
        exit(1);
      }
      
      if (!flood)
        sleep(1);
    }
    if (k >= 0)
      k++;
  }

  /* close the connections */
  for (i = offset; i < num + offset; i++)
    if ((close_connection(s->sockets[i])) < 0) {
      syslog(LOG_ERR, "PID %d: Error closing connection n:o: %d\n", 
             getpid(), i + 1);
      free(data);
      exit(1);
    }
  
  free(data);
  exit(0);
}
