/*  
    VTun - Virtual Tunnel over TCP/IP network.

    Copyright (C) 1998-2008  Maxim Krasnyansky <max_mk@yahoo.com>

    VTun has been derived from VPPP package by Maxim Krasnyansky. 

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
 */

/*
 * $Id: tcp_proto.c,v 1.7.2.2 2008/01/07 22:36:16 mtbishop Exp $
 */ 

#include "config.h"

#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <errno.h>

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#ifdef HAVE_NETINET_IN_SYSTM_H
#include <netinet/in_systm.h>
#endif

#ifdef HAVE_NETINET_IP_H
#include <netinet/ip.h>
#endif

#ifdef HAVE_NETINET_TCP_H
#include <netinet/tcp.h>
#endif

#include "vtun.h"
#include "lib.h"

int tcp_write(int fd, char *buf, int len)
{
     register char *ptr;

     ptr = buf - sizeof(short);

     *((unsigned short *)ptr) = htons(len); 
     len  = (len & VTUN_FSIZE_MASK) + sizeof(short);

     return write_n(fd, ptr, len);
}

int tcp_read(int fd, char *buf)
{
     unsigned short len, flen;
     register int rlen;     

     /* Read frame size */
     if( (rlen = read_n(fd, (char *)&len, sizeof(short)) ) <= 0)
	return rlen;

     len = ntohs(len);
     flen = len & VTUN_FSIZE_MASK;

     if( flen > VTUN_FRAME_SIZE + VTUN_FRAME_OVERHEAD ){
     	/* Oversized frame, drop it. */ 
        while( flen ){
	   len = min(flen, VTUN_FRAME_SIZE);
           if( (rlen = read_n(fd, buf, len)) <= 0 )
	      break;
           flen -= rlen;
        }                                                               
	return VTUN_BAD_FRAME;
     }	

     if( len & ~VTUN_FSIZE_MASK ){
	/* Return flags */
	return len;
     }

     /* Read frame */
     return read_n(fd, buf, flen);
}
