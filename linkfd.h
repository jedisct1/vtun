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
 * $Id: linkfd.h,v 1.4.2.3 2008/01/07 22:35:45 mtbishop Exp $
 */ 

#ifndef _LINKFD_H
#define _LINKFD_H

/* Priority of the process in the link_fd function */
/* Never set the priority to -19 without stating a good reason.
 *#define LINKFD_PRIO -19
 * Since the likely intent was just to give vtun an edge,
 * -1 will do nicely.
 */
#define LINKFD_PRIO -1
/* Frame alloc/free */
#define LINKFD_FRAME_RESERV 128
#define LINKFD_FRAME_APPEND 64

static inline void * lfd_alloc(size_t size)
{
     register char * buf;

     size += LINKFD_FRAME_RESERV + LINKFD_FRAME_APPEND;

     if( !(buf = malloc(size)) )
        return NULL;

     return buf+LINKFD_FRAME_RESERV; 
}

static inline void * lfd_realloc(void *buf, size_t size)
{
     unsigned char *ptr = buf;

     ptr  -= LINKFD_FRAME_RESERV;
     size += LINKFD_FRAME_RESERV;

     if( !(ptr = realloc(ptr, size)) )
        return NULL;

     return ptr+LINKFD_FRAME_RESERV; 
}

static inline void lfd_free(void *buf)
{
     unsigned char *ptr = buf;

     free(ptr-LINKFD_FRAME_RESERV);
}

int linkfd(struct vtun_host *host);

/* Module */
struct lfd_mod {
   char *name;
   int (*alloc)(struct vtun_host *host);
   int (*encode)(int len, char *in, char **out);
   int (*avail_encode)(void);
   int (*decode)(int len, char *in, char **out);
   int (*avail_decode)(void);
   int (*free)(void);

   struct lfd_mod *next;
   struct lfd_mod *prev;
};

/* External LINKFD modules */

extern struct lfd_mod lfd_zlib;
extern struct lfd_mod lfd_lzo;
extern struct lfd_mod lfd_encrypt;
extern struct lfd_mod lfd_legacy_encrypt;
extern struct lfd_mod lfd_shaper;

#endif
