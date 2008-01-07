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
 * $Id: lock.h,v 1.3.2.2 2008/01/07 22:35:51 mtbishop Exp $
 */ 

#ifndef _VTUN_LOCK_H
#define _VTUN_LOCK_H

pid_t read_lock(char * host);
int   create_lock(char * host);
int   lock_host(struct vtun_host * host);
void  unlock_host(struct vtun_host * host);

#endif /* _VTUN_LOCK_H */
