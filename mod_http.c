/*
 * Copyright (c) 1994, 1995, 1996
 *	Ohio University.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that: (1) source code
 * distributions retain the above copyright notice and this paragraph
 * in its entirety, (2) distributions including binary code include
 * the above copyright notice and this paragraph in its entirety in
 * the documentation or other materials provided with the
 * distribution, and (3) all advertising materials mentioning features
 * or use of this software display the following acknowledgment:
 * ``This product includes software developed by the Ohio University
 * Internetworking Research Laboratory.''  Neither the name of the
 * University nor the names of its contributors may be used to endorse
 * or promote products derived from this software without specific
 * prior written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 * 
 * Author:	Shawn Ostermann
 * 		School of Electrical Engineering and Computer Science
 * 		Ohio University
 * 		Athens, OH
 *		ostermann@cs.ohiou.edu
 */
static char const rcsid_http[] =
   "$Id: mod_http.c,v 1.4 1997/07/16 16:12:11 sdo Exp $";

#include "tcptrace.h"


#define DEFAULT_SERVER_PORT 80



static
struct http_info {
    timeval syn_time;		/* when CLIENT sent SYN */
    timeval get_time;		/* when CLIENT sent GET */
    timeval lastack_time;	/* when CLIENT acked last byte of server data */
    timeval fin_time;		/* when SERVER sent FIN */
    unsigned content_length;	/* as reported by server */
    unsigned byte_count;	/* as counted by tcptrace */
    char path[1024];		/* content of GET string */

    seqnum highest_data;	/* highest data byte from server */

    tcp_pair *ptp;

    int persist_count;		/* how many times this connection used? */

    struct http_info *pnext;
} *httphead = NULL;

static unsigned httpd_port;


/* Mostly as a module example, here's a plug in that records HTTP info */
int
http_init(
    int argc,
    char *argv[])
{
    int i;
    int enable=0;

    for (i=0; i < argc; ++i) {
	if (strncmp(argv[i],"-H",2) == 0) {
	    /* I want to be called */
	    enable = 1;
	    if (isdigit(argv[i][2])) {
		httpd_port = atoi(argv[i]+2);
	    } else {
		httpd_port = DEFAULT_SERVER_PORT;
	    }
	    fprintf(stderr,"Capturing HTTP traffic (port %d)\n",
		    httpd_port);
	    argv[i] = NULL;
	}
    }

    if (!enable)
	return(0);	/* don't call me again */


    /* init stuff */
    

    return(1);	/* TRUE means call http_read and http_done later */
}

static struct http_info *
MakeHttpRec()
{
    struct http_info *ph;

    ph = MallocZ(sizeof(struct http_info));
    ph->pnext = httphead;
    httphead = ph;

    return(ph);
}


void
http_read(
    struct ip *pip,	/* the packet */
    tcp_pair *ptp,	/* info I have about this connection */
    void *plast)	/* past byte in the packet */
{
    struct http_info *ph;
    struct tcphdr *ptcp;
    unsigned tcp_length;
    unsigned tcp_data_length;
    char *pget;
    char *pch;
    char *pdata;
    Bool client;
    int j;

    /* find the start of the TCP header */
    ptcp = (struct tcphdr *) ((char *)pip + 4*pip->ip_hl);
    tcp_length = pip->ip_len - (4 * pip->ip_hl);
    tcp_data_length = tcp_length - (4 * ptcp->th_off);

    /* verify port */
    if ((ptcp->th_sport != httpd_port) && (ptcp->th_dport != httpd_port))
	return;

    /* find the record for this packet */
    for (ph=httphead; ph; ph=ph->pnext) {
	if (ph->ptp == ptp)
	    break;
    }

    if (!ph) {
	/* didn't find it, make one up */
	ph = MakeHttpRec();
	ph->ptp = ptp;
	ph->persist_count = 1;

	/* record SYN time */
	if (SYN_SET(ptcp) && (ph->syn_time.tv_sec == 0))
	    ph->syn_time = current_time;
    }

    /* Is this packet from the client or not? */
    client = (ptcp->th_dport == httpd_port);

    /* find the data */
    pdata = (char *)ptcp + (unsigned)ptcp->th_off*4;

    /* print out the raw TCP data */
    PrintRawData("TCP Data",pdata,plast);

    /* look for GET */
    if (client) {
	for (pch = pdata; pch <= (char *)plast; ++pch) {
	    if (strncasecmp(pch,"get ", 4) == 0) {
		/* if this is a persistant connection, make a new one
		   database entry */
		if (ph->get_time.tv_sec != 0) {
		    int count = ph->persist_count;
/* 		    fprintf(stderr,"FOUND PERSISTANT CONNECTION\n"); */
		    ph = MakeHttpRec();
		    ph->ptp = ptp;
		    ph->persist_count = count+1;
		}

		for (j=0,pget = pch+4; ; ++j,++pget) {
		    if ((*pget == '\n') || (j >= sizeof(ph->path))) {
			ph->path[j+1] = '\00';
			pch = plast;  /* break out, ugly */
			break;
		    }
		    ph->path[j] = *pget;
		}
		ph->get_time = current_time;
	    }
	}
    }
    
    /* we want the time that the SERVER sends his FIN */
    if (!client)
	if (FIN_SET(ptcp) && (ph->fin_time.tv_sec == 0))
	    ph->fin_time = current_time;

    /* we want the time that the Client ACKS the last data byte
       from the server (ICK!) */
    if (!client && (tcp_data_length > 0)) { /* server data */
	seqnum lastbyte = ptcp->th_seq + tcp_data_length - 1;
	if (lastbyte > ph->highest_data)
	    ph->highest_data = lastbyte;
    }
    if (client && ACK_SET(ptcp)) {
	/* does this ACK "highest_data"? */
	if (SEQ_GREATERTHAN(ptcp->th_ack,ph->highest_data)) {
	    ph->lastack_time = current_time;
	}
    }

    /* look for Content_Length: */
    if (!client && (ph->content_length == 0)) {
	for (pch = pdata; pch <= (char *)plast; ++pch) {
	    if (strncasecmp(pch,"Content-Length:", 15) == 0) {
		/* find the value */
		ph->content_length = atoi(&pch[16]);
	    }
	}
    }

    /* at least count the bytes */
    if (!client) {
	ph->byte_count += tcp_data_length;
    }
}


static double
ts2d(timeval *pt)
{
    double d;
    d = pt->tv_sec;
    d += (double)pt->tv_usec/1000000;
    return(d);
}


static void
http_printone(
    MFILE *pmf,
    struct http_info *ph)
{
    tcp_pair *ptp = ph->ptp;
    double etime;

    if (!ptp)
	return;
	
    printf("%s ==> %s (%s2%s)\n",
	   ptp->a_endpoint, ptp->b_endpoint,
	   ptp->a2b.host_letter, ptp->b2a.host_letter);

    printf("\tSyn Time:      %s (%.3f)\n",
	   ts2ascii(&ph->syn_time),
	   ts2d(&ph->syn_time));
    printf("\tGet Time:      %s (%.3f)\n",
	   ts2ascii(&ph->get_time),
	   ts2d(&ph->get_time));
    printf("\tLastack Time:  %s (%.3f)\n",
	   ts2ascii(&ph->lastack_time),
	   ts2d(&ph->lastack_time));
    printf("\tFin Time:      %s (%.3f)\n",
	   ts2ascii(&ph->fin_time),
	   ts2d(&ph->fin_time));
    printf("\tGet string:    %s\n", ph->path);
    printf("\tContent len:   %d bytes (server string)\n", ph->content_length);
    printf("\tByte count:    %d bytes (by count)\n", ph->byte_count);
    etime = elapsed(ph->get_time,ph->lastack_time);
    etime /= 1000000;  /* us to secs */
    printf("\tElapsed time:  %.3f seconds (GET to LASTACK)\n", etime);
    printf("\tPersist count: %d\n", ph->persist_count);

    Mfprintf(pmf,"%.3f %.3f %.3f %.3f %d %s\n",
	     ts2d(&ph->syn_time),
	     ts2d(&ph->get_time),
	     ts2d(&ph->lastack_time),
	     ts2d(&ph->fin_time),
	     ph->content_length,
	     ph->path);
}


/* print the linked list, recursively, in reverse order (for Mark) */
static void
http_print(
    MFILE *pmf,
    struct http_info *ph)
{
    if (ph == NULL)
	return;

    http_print(pmf,ph->pnext);

    http_printone(pmf,ph);
}



void
http_done(void)
{
    MFILE *pmf;

    /* just return if we didn't grab anything */
    if (!httphead)
	return;

    pmf = Mfopen("http.times","w");

    printf("Http module output:\n");

    http_print(pmf,httphead);

    Mfclose(pmf);
}


void
http_usage(void)
{
    printf("\t\t-H[P]\tprint info about http traffic (on port P, default %d)\n",
	   DEFAULT_SERVER_PORT);
}
