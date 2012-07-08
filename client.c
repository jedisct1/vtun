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
 * $Id: client.c,v 1.11.2.3 2012/07/08 05:32:57 mtbishop Exp $
 */ 

#include "config.h"
#include "vtun_socks.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <syslog.h>

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#include "vtun.h"
#include "lib.h"
#include "llist.h"
#include "auth.h"
#include "compat.h"
#include "netlib.h"

static volatile sig_atomic_t client_term;
static void sig_term(int sig)
{
     vtun_syslog(LOG_INFO,"Terminated");
     client_term = VTUN_SIG_TERM;
}

void client(struct vtun_host *host)
{
     struct sockaddr_in my_addr,svr_addr;
     struct sigaction sa;
     int s, opt, reconnect;	

     vtun_syslog(LOG_INFO,"VTun client ver %s started",VTUN_VER);

     memset(&sa,0,sizeof(sa));     
     sa.sa_handler=SIG_IGN;
     sa.sa_flags = SA_NOCLDWAIT;
     sigaction(SIGHUP,&sa,NULL);
     sigaction(SIGQUIT,&sa,NULL);
     sigaction(SIGPIPE,&sa,NULL);
     sigaction(SIGCHLD,&sa,NULL);

     sa.sa_handler=sig_term;
     sigaction(SIGTERM,&sa,NULL);
     sigaction(SIGINT,&sa,NULL);
 
     client_term = 0; reconnect = 0;
     while( (!client_term) || (client_term == VTUN_SIG_HUP) ){
	if( reconnect && (client_term != VTUN_SIG_HUP) ){
	   if( vtun.persist || host->persist ){
	      /* Persist mode. Sleep and reconnect. */
	      sleep(5);
           } else {
	      /* Exit */
	      break;
	   }
	} else {
	   reconnect = 1;
        }

	set_title("%s init initializing", host->host);

	/* Set server address */
        if( server_addr(&svr_addr, host) < 0 )
	   continue;

	/* Set local address */
	if( local_addr(&my_addr, host, 0) < 0 )
	   continue;

	/* We have to create socket again every time
	 * we want to connect, since STREAM sockets 
	 * can be successfully connected only once.
	 */
        if( (s = socket(AF_INET,SOCK_STREAM,0))==-1 ){
	   vtun_syslog(LOG_ERR,"Can't create socket. %s(%d)", 
		strerror(errno), errno);
	   continue;
        }

	/* Required when client is forced to bind to specific port */
        opt=1;
        setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)); 

        if( bind(s,(struct sockaddr *)&my_addr,sizeof(my_addr)) ){
	   vtun_syslog(LOG_ERR,"Can't bind socket. %s(%d)",
		strerror(errno), errno);
	   continue;
        }

        /* 
         * Clear speed and flags which will be supplied by server. 
         */
        host->spd_in = host->spd_out = 0;
        host->flags &= VTUN_CLNT_MASK;

	io_init();

	set_title("%s connecting to %s", host->host, vtun.svr_name);
	if (!vtun.quiet)
	   vtun_syslog(LOG_INFO,"Connecting to %s", vtun.svr_name);

        if( connect_t(s,(struct sockaddr *) &svr_addr, host->timeout) ){
	   if (!vtun.quiet || errno != ETIMEDOUT)
	      vtun_syslog(LOG_INFO,"Connect to %s failed. %s(%d)", vtun.svr_name,
					strerror(errno), errno);
        } else {
	   if( auth_client(s, host) ){   
	      vtun_syslog(LOG_INFO,"Session %s[%s] opened",host->host,vtun.svr_name);

 	      host->rmt_fd = s;

	      /* Start the tunnel */
	      client_term = tunnel(host);

	      vtun_syslog(LOG_INFO,"Session %s[%s] closed",host->host,vtun.svr_name);
	   } else {
	      vtun_syslog(LOG_INFO,"Connection denied by %s",vtun.svr_name);
	   }
	}
	close(s);
	free_sopt(&host->sopt);
     }

     vtun_syslog(LOG_INFO, "Exit");
     return;
}
