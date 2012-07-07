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
 * $Id: linkfd.c,v 1.13.2.5 2012/07/07 07:14:17 mtbishop Exp $
 */

#include "config.h"
 
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <strings.h>
#include <string.h>
#include <errno.h>
#include <sys/time.h>
#include <syslog.h>
#include <time.h>

#ifdef HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif

#ifdef HAVE_SCHED_H
#include <sched.h>
#endif

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#include "vtun.h"
#include "linkfd.h"
#include "lib.h"
#include "driver.h"

/* used by lfd_encrypt */
int send_a_packet = 0;

/* Host we are working with. 
 * Used by signal handlers that's why it is global. 
 */
struct vtun_host *lfd_host;

struct lfd_mod *lfd_mod_head = NULL, *lfd_mod_tail = NULL;

/* Modules functions*/

/* Add module to the end of modules list */
void lfd_add_mod(struct lfd_mod *mod)
{
     if( !lfd_mod_head ){
        lfd_mod_head = lfd_mod_tail = mod;
	mod->next = mod->prev = NULL;
     } else {
        lfd_mod_tail->next = mod;
        mod->prev = lfd_mod_tail;
        mod->next = NULL;
        lfd_mod_tail = mod;
     }
}

/*  Initialize and allocate each module */
int lfd_alloc_mod(struct vtun_host *host)
{
     struct lfd_mod *mod = lfd_mod_head;

     while( mod ){
        if( mod->alloc && (mod->alloc)(host) )
	   return 1; 
	mod = mod->next;
     } 

     return 0;
}

/* Free all modules */
int lfd_free_mod(void)
{
     struct lfd_mod *mod = lfd_mod_head;

     while( mod ){
        if( mod->free && (mod->free)() )
	   return 1;
	mod = mod->next;
     } 
     lfd_mod_head = lfd_mod_tail = NULL;
     return 0;
}

 /* Run modules down (from head to tail) */
inline int lfd_run_down(int len, char *in, char **out)
{
     register struct lfd_mod *mod;
     
     *out = in;
     for(mod = lfd_mod_head; mod && len > 0; mod = mod->next )
        if( mod->encode ){
           len = (mod->encode)(len, in, out);
           in = *out;
        }
     return len;
}

/* Run modules up (from tail to head) */
inline int lfd_run_up(int len, char *in, char **out)
{
     register struct lfd_mod *mod;
     
     *out = in;
     for(mod = lfd_mod_tail; mod && len > 0; mod = mod->prev )
        if( mod->decode ){
	   len = (mod->decode)(len, in, out);
           in = *out;
	}
     return len;
}

/* Check if modules are accepting the data(down) */
inline int lfd_check_down(void)
{
     register struct lfd_mod *mod;
     int err = 1;
 
     for(mod = lfd_mod_head; mod && err > 0; mod = mod->next )
        if( mod->avail_encode )
           err = (mod->avail_encode)();
     return err;
}

/* Check if modules are accepting the data(up) */
inline int lfd_check_up(void)
{
     register struct lfd_mod *mod;
     int err = 1;

     for(mod = lfd_mod_tail; mod && err > 0; mod = mod->prev)
        if( mod->avail_decode )
           err = (mod->avail_decode)();

     return err;
}
		
/********** Linker *************/
/* Termination flag */
static volatile sig_atomic_t linker_term;

static void sig_term(int sig)
{
     vtun_syslog(LOG_INFO, "Closing connection");
     io_cancel();
     linker_term = VTUN_SIG_TERM;
}

static void sig_hup(int sig)
{
     vtun_syslog(LOG_INFO, "Reestablishing connection");
     io_cancel();
     linker_term = VTUN_SIG_HUP;
}

/* Statistic dump and keep-alive monitor */
static volatile sig_atomic_t ka_need_verify = 0;
static time_t stat_timer = 0, ka_timer = 0; 

void sig_alarm(int sig)
{
     static time_t tm_old, tm = 0;
     static char stm[20];
 
     tm_old = tm;
     tm = time(NULL);

     if( (lfd_host->flags & VTUN_KEEP_ALIVE) && (ka_timer -= tm-tm_old) <= 0){
	ka_need_verify = 1;
	ka_timer = lfd_host->ka_interval
	  + 1; /* We have to complete select() on idle */
     }

     if( (lfd_host->flags & VTUN_STAT) && (stat_timer -= tm-tm_old) <= 0){
        strftime(stm, sizeof(stm)-1, "%b %d %H:%M:%S", localtime(&tm)); 
        fprintf(lfd_host->stat.file,"%s %lu %lu %lu %lu\n", stm, 
	   lfd_host->stat.byte_in, lfd_host->stat.byte_out,
	   lfd_host->stat.comp_in, lfd_host->stat.comp_out); 
	stat_timer = VTUN_STAT_IVAL;
     }

     if ( ka_timer*stat_timer ){
       alarm( (ka_timer < stat_timer) ? ka_timer : stat_timer );
     } else {
       alarm( (ka_timer) ? ka_timer : stat_timer );
     }
}

static void sig_usr1(int sig)
{
     /* Reset statistic counters on SIGUSR1 */
     lfd_host->stat.byte_in = lfd_host->stat.byte_out = 0;
     lfd_host->stat.comp_in = lfd_host->stat.comp_out = 0; 
}

int lfd_linker(void)
{
     int fd1 = lfd_host->rmt_fd;
     int fd2 = lfd_host->loc_fd; 
     register int len, fl;
     struct timeval tv;
     char *buf, *out;
     fd_set fdset;
     int maxfd, idle = 0, tmplen;

     if( !(buf = lfd_alloc(VTUN_FRAME_SIZE + VTUN_FRAME_OVERHEAD)) ){
	vtun_syslog(LOG_ERR,"Can't allocate buffer for the linker"); 
        return 0; 
     }
	
     /* Delay sending of first UDP packet over broken NAT routers
	because we will probably be disconnected.  Wait for the remote
	end to send us something first, and use that connection. */
     if (!VTUN_USE_NAT_HACK(lfd_host))
        proto_write(fd1, buf, VTUN_ECHO_REQ);

     maxfd = (fd1 > fd2 ? fd1 : fd2) + 1;

     linker_term = 0;
     while( !linker_term ){
	errno = 0;

        /* Wait for data */
        FD_ZERO(&fdset);
	FD_SET(fd1, &fdset);
	FD_SET(fd2, &fdset);

 	tv.tv_sec  = lfd_host->ka_interval;
	tv.tv_usec = 0;

	if( (len = select(maxfd, &fdset, NULL, NULL, &tv)) < 0 ){
	   if( errno != EAGAIN && errno != EINTR )
	      break;
	   else
	      continue;
	} 

	if( ka_need_verify ){
	  if( idle > lfd_host->ka_maxfail ){
	    vtun_syslog(LOG_INFO,"Session %s network timeout", lfd_host->host);
	    break;
	  }
	  if (idle++ > 0) {  /* No input frames, check connection with ECHO */
	    if( proto_write(fd1, buf, VTUN_ECHO_REQ) < 0 ){
	      vtun_syslog(LOG_ERR,"Failed to send ECHO_REQ");
	      break;
	    }
	  }
	  ka_need_verify = 0;
	}

	if (send_a_packet)
        {
           send_a_packet = 0;
           tmplen = 1;
	   lfd_host->stat.byte_out += tmplen; 
	   if( (tmplen=lfd_run_down(tmplen,buf,&out)) == -1 )
	      break;
	   if( tmplen && proto_write(fd1, out, tmplen) < 0 )
	      break;
	   lfd_host->stat.comp_out += tmplen; 
        }

	/* Read frames from network(fd1), decode and pass them to 
         * the local device (fd2) */
	if( FD_ISSET(fd1, &fdset) && lfd_check_up() ){
	   idle = 0;  ka_need_verify = 0;
	   if( (len=proto_read(fd1, buf)) <= 0 )
	      break;

	   /* Handle frame flags */
	   fl = len & ~VTUN_FSIZE_MASK;
           len = len & VTUN_FSIZE_MASK;
	   if( fl ){
	      if( fl==VTUN_BAD_FRAME ){
		 vtun_syslog(LOG_ERR, "Received bad frame");
		 continue;
	      }
	      if( fl==VTUN_ECHO_REQ ){
		 /* Send ECHO reply */
	 	 if( proto_write(fd1, buf, VTUN_ECHO_REP) < 0 )
		    break;
		 continue;
	      }
   	      if( fl==VTUN_ECHO_REP ){
		 /* Just ignore ECHO reply, ka_need_verify==0 already */
		 continue;
	      }
	      if( fl==VTUN_CONN_CLOSE ){
	         vtun_syslog(LOG_INFO,"Connection closed by other side");
		 break;
	      }
	   }   

	   lfd_host->stat.comp_in += len; 
	   if( (len=lfd_run_up(len,buf,&out)) == -1 )
	      break;	
	   if( len && dev_write(fd2,out,len) < 0 ){
              if( errno != EAGAIN && errno != EINTR )
                 break;
              else
                 continue;
           }
	   lfd_host->stat.byte_in += len; 
	}

	/* Read data from the local device(fd2), encode and pass it to 
         * the network (fd1) */
	if( FD_ISSET(fd2, &fdset) && lfd_check_down() ){
	   if( (len = dev_read(fd2, buf, VTUN_FRAME_SIZE)) < 0 ){
	      if( errno != EAGAIN && errno != EINTR )
	         break;
	      else
		 continue;
	   }
	   if( !len ) break;
	
	   lfd_host->stat.byte_out += len; 
	   if( (len=lfd_run_down(len,buf,&out)) == -1 )
	      break;
	   if( len && proto_write(fd1, out, len) < 0 )
	      break;
	   lfd_host->stat.comp_out += len; 
	}
     }
     if( !linker_term && errno )
	vtun_syslog(LOG_INFO,"%s (%d)", strerror(errno), errno);

     if (linker_term == VTUN_SIG_TERM) {
       lfd_host->persist = 0;
     }

     /* Notify other end about our close */
     proto_write(fd1, buf, VTUN_CONN_CLOSE);
     lfd_free(buf);

     return 0;
}

/* Link remote and local file descriptors */ 
int linkfd(struct vtun_host *host)
{
     struct sigaction sa, sa_oldterm, sa_oldint, sa_oldhup;
     int old_prio;

     lfd_host = host;
 
     old_prio=getpriority(PRIO_PROCESS,0);
     setpriority(PRIO_PROCESS,0,LINKFD_PRIO);

     /* Build modules stack */
     if(host->flags & VTUN_ZLIB)
	lfd_add_mod(&lfd_zlib);

     if(host->flags & VTUN_LZO)
	lfd_add_mod(&lfd_lzo);

     if(host->flags & VTUN_ENCRYPT)
       if(host->cipher == VTUN_LEGACY_ENCRYPT) {
	 lfd_add_mod(&lfd_legacy_encrypt);
       } else {
	 lfd_add_mod(&lfd_encrypt);
       }
     
     if(host->flags & VTUN_SHAPE)
	lfd_add_mod(&lfd_shaper);

     if(lfd_alloc_mod(host))
	return 0;

     memset(&sa, 0, sizeof(sa));
     sa.sa_handler=sig_term;
     sigaction(SIGTERM,&sa,&sa_oldterm);
     sigaction(SIGINT,&sa,&sa_oldint);
     sa.sa_handler=sig_hup;
     sigaction(SIGHUP,&sa,&sa_oldhup);

     /* Initialize keep-alive timer */
     if( host->flags & (VTUN_STAT|VTUN_KEEP_ALIVE) ){
        sa.sa_handler=sig_alarm;
        sigaction(SIGALRM,&sa,NULL);

	alarm( (host->ka_interval < VTUN_STAT_IVAL) ?
		host->ka_interval : VTUN_STAT_IVAL );
     }

     /* Initialize statstic dumps */
     if( host->flags & VTUN_STAT ){
	char file[40];

        sa.sa_handler=sig_alarm;
        sigaction(SIGALRM,&sa,NULL);
        sa.sa_handler=sig_usr1;
        sigaction(SIGUSR1,&sa,NULL);

	sprintf(file,"%s/%.20s", VTUN_STAT_DIR, host->host);
	if( (host->stat.file=fopen(file, "a")) ){
	   setvbuf(host->stat.file, NULL, _IOLBF, 0);
	} else
	   vtun_syslog(LOG_ERR, "Can't open stats file %s", file);
     }

     io_init();

     lfd_linker();

     if( host->flags & (VTUN_STAT|VTUN_KEEP_ALIVE) ){
        alarm(0);
	if (host->stat.file)
	  fclose(host->stat.file);
     }

     lfd_free_mod();
     
     sigaction(SIGTERM,&sa_oldterm,NULL);
     sigaction(SIGINT,&sa_oldint,NULL);
     sigaction(SIGHUP,&sa_oldhup,NULL);

     setpriority(PRIO_PROCESS,0,old_prio);

     return linker_term;
}
