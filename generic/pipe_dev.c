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
 * $Id: pipe_dev.c,v 1.4.2.2 2008/01/07 22:36:12 mtbishop Exp $
 */ 

#include "config.h"

#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <sys/socket.h>

#include "vtun.h"
#include "lib.h"

/* 
 * Create pipe. Return open fd. 
 */  
int pipe_open(int *fd)
{
    return socketpair(AF_UNIX, SOCK_STREAM, 0, fd);
}

/* Write frames to pipe */
int pipe_write(int fd, char *buf, int len)
{
    return write_n(fd, buf, len);
}

/* Read frames from pipe */
int pipe_read(int fd, char *buf, int len)
{
    return read(fd, buf, len);
}
