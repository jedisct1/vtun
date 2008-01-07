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
 * $Id: tunnel.c,v 1.14.2.2 2008/01/07 22:36:03 mtbishop Exp $
 */ 

#include "config.h"

#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdarg.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <syslog.h>
#include <signal.h>

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
#include "linkfd.h"
#include "lib.h"
#include "netlib.h"
#include "driver.h"

int (*dev_write)(int fd, char *buf, int len);
int (*dev_read)(int fd, char *buf, int len);

int (*proto_write)(int fd, char *buf, int len);
int (*proto_read)(int fd, char *buf);

/* Initialize and start the tunnel.
   Returns:
      -1 - critical error
      0  - normal close or noncritical error 
*/
   
int tunnel(struct vtun_host *host)
{
     int null_fd, pid, opt;
     int fd[2]={-1, -1};
     char dev[VTUN_DEV_LEN]="";
     int interface_already_open = 0;

     if ( (host->persist == VTUN_PERSIST_KEEPIF) &&
	  (host->loc_fd >= 0) )
        interface_already_open = 1;

     /* Initialize device. */
     if( host->dev ){
        strncpy(dev, host->dev, VTUN_DEV_LEN);
	dev[VTUN_DEV_LEN-1]='\0';
     }
     if( ! interface_already_open ){
        switch( host->flags & VTUN_TYPE_MASK ){
           case VTUN_TTY:
	      if( (fd[0]=pty_open(dev)) < 0 ){
		 vtun_syslog(LOG_ERR,"Can't allocate pseudo tty. %s(%d)", strerror(errno), errno);
		 return -1;
	      }
	      break;

           case VTUN_PIPE:
	      if( pipe_open(fd) < 0 ){
		 vtun_syslog(LOG_ERR,"Can't create pipe. %s(%d)", strerror(errno), errno);
		 return -1;
	      }
	      break;

           case VTUN_ETHER:
	      if( (fd[0]=tap_open(dev)) < 0 ){
		 vtun_syslog(LOG_ERR,"Can't allocate tap device %s. %s(%d)", dev, strerror(errno), errno);
		 return -1;
	      }
	      break;

	   case VTUN_TUN:
	      if( (fd[0]=tun_open(dev)) < 0 ){
		 vtun_syslog(LOG_ERR,"Can't allocate tun device %s. %s(%d)", dev, strerror(errno), errno);
		 return -1;
	      }
	      break;
	}
	host->loc_fd = fd[0];
     }
     host->sopt.dev = strdup(dev);

     /* Initialize protocol. */
     switch( host->flags & VTUN_PROT_MASK ){
        case VTUN_TCP:
	   opt=1;
	   setsockopt(host->rmt_fd,SOL_SOCKET,SO_KEEPALIVE,&opt,sizeof(opt) );

	   opt=1;
	   setsockopt(host->rmt_fd,IPPROTO_TCP,TCP_NODELAY,&opt,sizeof(opt) );

	   proto_write = tcp_write;
	   proto_read  = tcp_read;

	   break;

        case VTUN_UDP:
	   if( (opt = udp_session(host)) == -1){
	      vtun_syslog(LOG_ERR,"Can't establish UDP session");
	      close(fd[1]);
	      if( ! ( host->persist == VTUN_PERSIST_KEEPIF ) )
		 close(fd[0]);
	      return 0;
	   } 	

 	   proto_write = udp_write;
	   proto_read = udp_read;

	   break;
     }

        switch( (pid=fork()) ){
	   case -1:
	      vtun_syslog(LOG_ERR,"Couldn't fork()");
	      if( ! ( host->persist == VTUN_PERSIST_KEEPIF ) )
		 close(fd[0]);
	      close(fd[1]);
	      return 0;
 	   case 0:
           /* do this only the first time when in persist = keep mode */
           if( ! interface_already_open ){
	      switch( host->flags & VTUN_TYPE_MASK ){
	         case VTUN_TTY:
		    /* Open pty slave (becomes controlling terminal) */
		    if( (fd[1] = open(dev, O_RDWR)) < 0){
		       vtun_syslog(LOG_ERR,"Couldn't open slave pty");
		       exit(0);
		    }
		    /* Fall through */
	         case VTUN_PIPE:
		    null_fd = open("/dev/null", O_RDWR);
		    close(fd[0]);
		    close(0); dup(fd[1]);
		    close(1); dup(fd[1]);
		    close(fd[1]);

		    /* Route stderr to /dev/null */
		    close(2); dup(null_fd);
		    close(null_fd);
		    break;
	         case VTUN_ETHER:
	         case VTUN_TUN:
		    break;
	      }
           }
	   /* Run list of up commands */
	   set_title("%s running up commands", host->host);
	   llist_trav(&host->up, run_cmd, &host->sopt);

	   exit(0);           
	}

     switch( host->flags & VTUN_TYPE_MASK ){
        case VTUN_TTY:
	   set_title("%s tty", host->host);

	   dev_read  = pty_read;
	   dev_write = pty_write; 
	   break;

        case VTUN_PIPE:
	   /* Close second end of the pipe */
	   close(fd[1]);
	   set_title("%s pipe", host->host);

	   dev_read  = pipe_read;
	   dev_write = pipe_write; 
	   break;

        case VTUN_ETHER:
	   set_title("%s ether %s", host->host, dev);

	   dev_read  = tap_read;
	   dev_write = tap_write; 
	   break;

        case VTUN_TUN:
	   set_title("%s tun %s", host->host, dev);

	   dev_read  = tun_read;
	   dev_write = tun_write; 
	   break;
     }

     opt = linkfd(host);

     set_title("%s running down commands", host->host);
     llist_trav(&host->down, run_cmd, &host->sopt);

     if(! ( host->persist == VTUN_PERSIST_KEEPIF ) ) {
        set_title("%s closing", host->host);

	/* Gracefully destroy interface */
	switch( host->flags & VTUN_TYPE_MASK ){
           case VTUN_TUN:
	      tun_close(fd[0], dev);
	      break;

           case VTUN_ETHER:
	      tap_close(fd[0], dev);
	      break;
	}

       	close(host->loc_fd);
     }

     /* Close all other fds */
     close(host->rmt_fd);
     close(fd[1]);

     return opt;
}
