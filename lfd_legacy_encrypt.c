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
 * $Id: lfd_legacy_encrypt.c,v 1.1.4.2 2008/01/07 22:35:33 mtbishop Exp $
 * Code added wholesale temporarily from lfd_encrypt 1.2.2.8
 */ 

/*
   Encryption module uses software developed by the OpenSSL Project
   for use in the OpenSSL Toolkit. (http://www.openssl.org/)       
   Copyright (c) 1998-2000 The OpenSSL Project.  All rights reserved.
 */

/*
 * This lfd_encrypt module uses MD5 to create 128 bits encryption
 * keys and BlowFish for actual data encryption.
 * It is based on code written by Chris Todd<christ@insynq.com> with 
 * several improvements and modifications.  
 */

#include "config.h"

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <syslog.h>
#include <strings.h>
#include <string.h>

#include "vtun.h"
#include "linkfd.h"
#include "lib.h"

#ifdef HAVE_SSL

#ifndef __APPLE_CC__
/* OpenSSL includes */
#include <openssl/md5.h>
#include <openssl/blowfish.h>
#else /* YAY - We're MAC OS */
#include <sys/md5.h>
#include <crypto/blowfish.h>
#endif  /* __APPLE_CC__ */

#define ENC_BUF_SIZE VTUN_FRAME_SIZE + 16 
#define ENC_KEY_SIZE 16

BF_KEY key;
char * enc_buf;

int alloc_legacy_encrypt(struct vtun_host *host)
{
   if( !(enc_buf = lfd_alloc(ENC_BUF_SIZE)) ){
      vtun_syslog(LOG_ERR,"Can't allocate buffer for legacy encryptor");
      return -1;
   }

   BF_set_key(&key, ENC_KEY_SIZE, MD5(host->passwd,strlen(host->passwd),NULL));

   vtun_syslog(LOG_INFO, "BlowFish legacy encryption initialized");
   return 0;
}

int free_legacy_encrypt()
{
   lfd_free(enc_buf); enc_buf = NULL;
   return 0;
}

int legacy_encrypt_buf(int len, char *in, char **out)
{ 
   register int pad, p;
   register char *in_ptr = in, *out_ptr = enc_buf;

   /* 8 - ( len % 8 ) */
   pad = (~len & 0x07) + 1; p = 8 - pad;

   memset(out_ptr, 0, pad);
   *out_ptr = (char) pad;
   memcpy(out_ptr + pad, in_ptr, p);  
   BF_ecb_encrypt(out_ptr, out_ptr, &key, BF_ENCRYPT);
   out_ptr += 8; in_ptr += p; 
   len = len - p;

   for (p=0; p < len; p += 8)
      BF_ecb_encrypt(in_ptr + p,  out_ptr + p, &key, BF_ENCRYPT);

   *out = enc_buf;
   return len + 8;
}

int legacy_decrypt_buf(int len, char *in, char **out)
{
   register int p;

   for (p = 0; p < len; p += 8)
      BF_ecb_encrypt(in + p, in + p, &key, BF_DECRYPT);

   p = *in;
   if (p < 1 || p > 8) {
      vtun_syslog(LOG_INFO, "legacy_decrypt_buf: bad pad length");
      return 0;
   }

   *out = in + p;

   return len - p;
}

/* 
 * Module structure.
 */
struct lfd_mod lfd_legacy_encrypt = {
     "Encryptor",
     alloc_legacy_encrypt,
     legacy_encrypt_buf,
     NULL,
     legacy_decrypt_buf,
     NULL,
     free_legacy_encrypt,
     NULL,
     NULL
};

#else  /* HAVE_SSL */

int no_legacy_encrypt(struct vtun_host *host)
{
     vtun_syslog(LOG_INFO, "Encryption is not supported");
     return -1;
}

struct lfd_mod lfd_legacy_encrypt = {
     "Encryptor",
     no_legacy_encrypt, NULL, NULL, NULL, NULL, NULL, NULL, NULL
};

#endif /* HAVE_SSL */
