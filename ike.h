/*

  ike.h

  Author: Pekka Riikonen <priikone@ssh.com>

  Copyright (c) 1999 - 2010 Pekka Riikonen, priikone@silcnet.org.

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.
 
  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#ifndef IKE_H
#define IKE_H

#include "conntest.h"

/* Starts IKE server and returns a context to the server. */
void *ike_start(void);

#define IKE_ATTACK_AGGR 1
#define IKE_ATTACK_MM 2

/* Adds new IKE negotiation to the IKE server and starts the negotiation.
   Each negotiation is run in own process. Each negotiation will end on
   its own after negotiation is finished. */
void ike_add(void *context, int sock, c_sockaddr *dest,
	     int flood, char *identity, int group, int auth,
	     int attack);

#endif /* IKE_H */
