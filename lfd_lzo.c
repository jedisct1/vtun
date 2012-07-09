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
 * $Id: lfd_lzo.c,v 1.5.2.5 2012/07/09 01:01:08 mtbishop Exp $
 */ 

/* LZO compression module */

#include "config.h"

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <syslog.h>

#include "vtun.h"
#include "linkfd.h"
#include "lib.h"

#ifdef HAVE_LZO

#include "lzoutil.h"
#include "lzo1x.h"
#include "lzoutil.h"

static lzo_byte *zbuf;
static lzo_voidp wmem;
static int zbuf_size = VTUN_FRAME_SIZE * VTUN_FRAME_SIZE / 64 + 16 + 3;

/* Pointer to compress function */
int (*lzo1x_compress)(const lzo_byte *src, lzo_uint  src_len,
		   	    lzo_byte *dst, lzo_uint *dst_len,
		   	    lzo_voidp wrkmem);
/* 
 * Initialize compressor/decompressor.
 * Allocate the buffers.
 */  

int alloc_lzo(struct vtun_host *host)
{
     int zlevel = host->zlevel ? host->zlevel : 1;
     lzo_uint mem;

     switch( zlevel ){
	case 9:
	   lzo1x_compress = lzo1x_999_compress;
           mem = LZO1X_999_MEM_COMPRESS;
           break;
	default: 	   
 	   lzo1x_compress = lzo1x_1_15_compress;
           mem = LZO1X_1_15_MEM_COMPRESS;
           break;
     }

     if( lzo_init() != LZO_E_OK ){
	vtun_syslog(LOG_ERR,"Can't initialize compressor");
	return 1;
     }	
     if( !(zbuf = lfd_alloc(zbuf_size)) ){
	vtun_syslog(LOG_ERR,"Can't allocate buffer for the compressor");
	return 1;
     }	
     if( !(wmem = lzo_malloc(mem)) ){
	vtun_syslog(LOG_ERR,"Can't allocate buffer for the compressor");
	return 1;
     }	

     vtun_syslog(LOG_INFO, "LZO compression[level %d] initialized", zlevel);

     return 0;
}

/* 
 * Deinitialize compressor/decompressor.
 * Free the buffer.
 */  

int free_lzo()
{
     lfd_free(zbuf); zbuf = NULL;
     lzo_free(wmem); wmem = NULL;
     return 0;
}

/* 
 * This functions _MUST_ consume all incoming bytes in one pass,
 * that's why we expand buffer dynamicly.
 */  
int comp_lzo(int len, char *in, char **out)
{ 
     lzo_uint zlen = 0;    
     int err;
     
     if( (err=lzo1x_compress((void *)in,len,zbuf,&zlen,wmem)) != LZO_E_OK ){
        vtun_syslog(LOG_ERR,"Compress error %d",err);
        return -1;
     }

     *out = (void *)zbuf;
     return zlen;
}

int decomp_lzo(int len, char *in, char **out)
{
     lzo_uint zlen = 0;
     int err;

     if( (err=lzo1x_decompress((void *)in,len,zbuf,&zlen,wmem)) != LZO_E_OK ){
        vtun_syslog(LOG_ERR,"Decompress error %d",err);
        return -1;
     }

     *out = (void *) zbuf;
     return zlen;
}

struct lfd_mod lfd_lzo = {
     "LZO",
     alloc_lzo,
     comp_lzo,
     NULL,
     decomp_lzo,
     NULL,
     free_lzo,
     NULL,
     NULL
};

#else  /* HAVE_LZO */

int no_lzo(struct vtun_host *host)
{
     vtun_syslog(LOG_INFO, "LZO compression is not supported");
     return -1;
}

struct lfd_mod lfd_lzo = {
     "LZO",
     no_lzo, NULL, NULL, NULL, NULL, NULL, NULL, NULL
};

#endif /* HAVE_LZO */


