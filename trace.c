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
static char const copyright[] =
    "@(#)Copyright (c) 1996 -- Ohio University.  All rights reserved.\n";
static char const rcsid[] =
    "@(#)$Header: /home/sdo/src/tcptrace/RCS/trace.c,v 3.15 1997/09/05 19:17:55 sdo Exp $";


#include "tcptrace.h"
#include "gcache.h"

/* locally global variables */
static int trace_count = 0;
static int packet_count = 0;
static int search_count = 0;
static Bool *ignore_pairs = NULL;/* which ones will we ignore */
static Bool bottom_letters = 0;
static Bool more_conns_ignored = FALSE;



/* provided globals  */
int num_tcp_pairs = -1;	/* how many pairs we've allocated */
tcp_pair **ttp = NULL;	/* array of pointers to allocated pairs */
int max_tcp_pairs = 64; /* initial value, automatically increases */


/* local routine definitions */
static void CopyAddr(tcp_pair_addrblock *, ipaddr,ipaddr,portnum,portnum);
static int WhichDir(tcp_pair_addrblock *, tcp_pair_addrblock *);
static int SameConn(tcp_pair_addrblock *, tcp_pair_addrblock *, int *);
static tcp_pair *NewTTP(struct ip *, struct tcphdr *);
static tcp_pair *FindTTP(struct ip *, struct tcphdr *, int *);
static void MoreTcpPairs(int num_needed);
static void ExtractContents(u_long seq, u_long tcp_data_bytes,
			    u_long saved_data_bytes, void *pdata, tcb *ptcb);



/* options */
Bool show_zero_window = TRUE;
Bool show_rexmit = TRUE;
Bool show_out_order = TRUE;
Bool show_sacks = TRUE;
Bool nonames = FALSE;
Bool use_short_names = FALSE;
int thru_interval = 10;	/* in segments */


/* what colors to use */
/* choose from: "green" "red" "blue" "yellow" "purple" "orange" "magenta" "pink" */
char *window_color	= "yellow";
char *ack_color		= "green";
char *sack_color	= "purple";
char *data_color	= "white";
char *retrans_color	= "red";
char *out_order_color	= "pink";
char *text_color	= "magenta";
char *default_color	= "white";
char *synfin_color	= "orange";
char *push_color	= "white";	/* top arrow for PUSHed segments */


/* return elapsed time in microseconds */
/* (time2 - time1) */
double
elapsed(
    struct timeval time1,
    struct timeval time2)
{
    struct timeval etime;

    etime.tv_sec  = time2.tv_sec  - time1.tv_sec;
    etime.tv_usec = time2.tv_usec - time1.tv_usec;
    if (etime.tv_usec < 0) {
	etime.tv_sec  -= 1;
	etime.tv_usec += 1000000;
    }
    return((double)etime.tv_sec * 1000000 + (double)etime.tv_usec);
}




/* WARNING, this routines "understands" the internal structure of IPv4 addresses */
/* will break under IPng... */
static void
CopyAddr(
    tcp_pair_addrblock *ptpa,
    ipaddr	ip1,
    ipaddr	ip2,
    portnum	port1,
    portnum	port2)
{
    IP_COPYADDR(ptpa->a_address, ip1);
    IP_COPYADDR(ptpa->b_address, ip2);
    ptpa->a_port = port1;
    ptpa->b_port = port2;

    /* fill in the hashed address */
    ptpa->hash = ptpa->a_address.s_addr + ptpa->b_address.s_addr
	+ ptpa->a_port + ptpa->b_port;
}



static int
WhichDir(
    tcp_pair_addrblock *ptpa1,
    tcp_pair_addrblock *ptpa2)
{

#ifdef BROKEN_COMPILER
    /* sorry for the ugly nested 'if', but a 4-way conjunction broke my	*/
    /* Optimizer (under 'gcc version cygnus-2.0.2')			*/

    /* same as first packet */
    if (IP_SAMEADDR(ptpa1->a_address, ptpa2->a_address))
	if (IP_SAMEADDR(ptpa1->b_address, ptpa2->b_address))
	    if ((ptpa1->a_port == ptpa2->a_port))
		if ((ptpa1->b_port == ptpa2->b_port))
		    return(A2B);

    /* reverse of first packet */
    if (IP_SAMEADDR(ptpa1->a_address, ptpa2->b_address))
	if (IP_SAMEADDR(ptpa1->b_address, ptpa2->a_address))
	    if ((ptpa1->a_port == ptpa2->b_port))
		if ((ptpa1->b_port == ptpa2->a_port))
		    return(B2A);
#else /* BROKEN_COMPILER */
    /* same as first packet */
    if (IP_SAMEADDR(ptpa1->a_address, ptpa2->a_address) &&
	IP_SAMEADDR(ptpa1->b_address, ptpa2->b_address) &&
	(ptpa1->a_port == ptpa2->a_port) &&
	(ptpa1->b_port == ptpa2->b_port))
	return(A2B);

    /* reverse of first packet */
    if (IP_SAMEADDR(ptpa1->a_address, ptpa2->b_address) &&
	IP_SAMEADDR(ptpa1->b_address, ptpa2->a_address) &&
	(ptpa1->a_port == ptpa2->b_port) &&
	(ptpa1->b_port == ptpa2->a_port))
	return(B2A);
#endif /* BROKEN_COMPILER */

    /* different connection */
    return(0);
}



static int
SameConn(
    tcp_pair_addrblock *ptpa1,
    tcp_pair_addrblock *ptpa2,
    int      *pdir)
{
    /* if the hash values are different, they can't be the same */
    if (ptpa1->hash != ptpa2->hash)
	return(0);

    /* OK, they hash the same, are they REALLY the same function */
    *pdir = WhichDir(ptpa1,ptpa2);
    return(*pdir != 0);
}


static tcp_pair *
NewTTP(
    struct ip *pip,
    struct tcphdr *ptcp)
{
    char title[210];
    tcp_pair *ptp;

    /* make a new one, if possible */
    if ((num_tcp_pairs+1) >= max_tcp_pairs) {
	MoreTcpPairs(num_tcp_pairs+1);
    }

    /* create a new TCP pair record and remember where you put it */
    ++num_tcp_pairs;
    ptp = ttp[num_tcp_pairs] = MallocZ(sizeof(tcp_pair));
    ptp->ignore_pair = ignore_pairs[num_tcp_pairs];


    /* grab the address from this packet */
    CopyAddr(&ptp->addr_pair, pip->ip_src, pip->ip_dst,
	     ntohs(ptcp->th_sport), ntohs(ptcp->th_dport));

    ptp->a2b.time.tv_sec = -1;
    ptp->b2a.time.tv_sec = -1;

    ptp->a2b.host_letter = strdup(HostLetter(2*num_tcp_pairs));
    ptp->b2a.host_letter = strdup(HostLetter((2*num_tcp_pairs) + 1));

    ptp->a2b.ptp = ptp;
    ptp->b2a.ptp = ptp;
    ptp->a2b.ptwin = &ptp->b2a;
    ptp->b2a.ptwin = &ptp->a2b;

    ptp->a_endpoint =
	strdup(EndpointName(ptp->addr_pair.a_address,
			    ptp->addr_pair.a_port));
    ptp->b_endpoint = 
	strdup(EndpointName(ptp->addr_pair.b_address,
			    ptp->addr_pair.b_port));

    ptp->a2b.tsg_plotter = ptp->b2a.tsg_plotter = -1;
    if (graph_tsg && !ptp->ignore_pair) {
	if (!ignore_non_comp || (SYN_SET(ptcp))) {
	    sprintf(title,"%s_==>_%s (time sequence graph)",
		    ptp->a_endpoint, ptp->b_endpoint);
	    ptp->a2b.tsg_plotter = new_plotter(&ptp->a2b,NULL,title,
					       "time","sequence number",
					       PLOT_FILE_EXTENSION);
	    sprintf(title,"%s_==>_%s (time sequence graph)",
		    ptp->b_endpoint, ptp->a_endpoint);
	    ptp->b2a.tsg_plotter = new_plotter(&ptp->b2a,NULL,title,
					       "time","sequence number",
					       PLOT_FILE_EXTENSION);
	}
    }

    ptp->a2b.ss = (seqspace *)MallocZ(sizeof(seqspace));
    ptp->b2a.ss = (seqspace *)MallocZ(sizeof(seqspace));

    return(ptp);
}



/* connection records are stored in a hash table.  Buckets are linked	*/
/* lists sorted by most recent access.					*/
#define HASH_TABLE_SIZE 1021  /* oughta be prime */
static tcp_pair *
FindTTP(
    struct ip *pip,
    struct tcphdr *ptcp,
    int *pdir)
{
    static tcp_pair *ptp_hashtable[HASH_TABLE_SIZE] = {NULL};
    tcp_pair **pptp_head = NULL;
    tcp_pair *ptp;
    tcp_pair *ptp_last;
    tcp_pair tp_in;
    int dir;
    hash hval;


    /* grab the address from this packet */
    CopyAddr(&tp_in.addr_pair, pip->ip_src, pip->ip_dst,
	     ntohs(ptcp->th_sport), ntohs(ptcp->th_dport));

    /* grab the hash value (already computed by CopyAddr) */
    hval = tp_in.addr_pair.hash % HASH_TABLE_SIZE;
    

    ptp_last = NULL;
    pptp_head = &ptp_hashtable[hval];
    for (ptp = *pptp_head; ptp; ptp=ptp->next) {
	++search_count;
	if (SameConn(&tp_in.addr_pair,&ptp->addr_pair,&dir)) {
	    /* check for "inactive" */
	    if (ptp->inactive)
		continue;

	    /* check for NEW connection on these same endpoints */
	    /* 1) At least 4 minutes idle time */
	    /*  AND */
	    /* 2) heuristic (we might miss some) either: */
	    /*    this packet has a SYN */
	    /*    last conn saw both FINs */
	    /* if so, mark it INACTIVE and skip from now on */
	    if (elapsed(ptp->last_time,current_time)/1000000 > (4*60)) {
		if ((SYN_SET(ptcp)) ||
		    ((ptp->a2b.fin_count >= 1) &&
		     (ptp->b2a.fin_count >= 1))) {
		    if (debug) {
			printf("%s: Marking 0x%08x %s<->%s INACTIVE (idle: %f sec)\n",
			       ts2ascii(&current_time),
			       (unsigned) ptp,
			       ptp->a_endpoint, ptp->b_endpoint,
			       elapsed(ptp->last_time,
				       current_time)/1000000);
			if (debug > 1)
			    PrintTrace(ptp);
		    }
		    ptp->inactive = TRUE;
		    continue;
		}
	    }

	    /* move to head of access list (unless already there) */
	    if (ptp != *pptp_head) {
		ptp_last->next = ptp->next; /* unlink */
		ptp->next = *pptp_head;	    /* move to head */
		*pptp_head = ptp;
	    }
	    *pdir = dir;
	    return(ptp);
	}
	ptp_last = ptp;
    }

    /* Didn't find it, make a new one, if possible */
    ptp = NewTTP(pip,ptcp);

    /* put at the head of the access list */
    if (ptp) {
	ptp->next = *pptp_head;
	*pptp_head = ptp;
    }

    *pdir = A2B;
    return(ptp);
}
     
 

tcp_pair *
dotrace(
    struct ip *pip,
    void *plast)
{
    struct tcphdr	*ptcp;
    struct tcp_options *ptcpo;
    tcp_pair	*ptp_save;
    unsigned	int tcp_length;
    unsigned	int tcp_data_length;
    u_long	start;
    u_long	end;
    tcb		*thisdir;
    tcb		*otherdir;
    tcp_pair	tp_in;
    PLOTTER	to_tsgpl;
    PLOTTER	from_tsgpl;
    int		dir;
    Bool	retrans;
    int		retrans_num_bytes;
    Bool	out_order;  /* out of order */
    u_short	th_sport;	/* source port */
    u_short	th_dport;	/* destination port */
    tcp_seq	th_seq;		/* sequence number */
    tcp_seq	th_ack;		/* acknowledgement number */
    u_short	th_win;		/* window */
    short	ip_len;		/* total length */

    /* find the start of the TCP header */
    ptcp = (struct tcphdr *) ((char *)pip + 4*pip->ip_hl);

    /* make sure we have enough of the packet */
    if ((unsigned)ptcp + sizeof(struct tcphdr)-1 > (unsigned)plast) {
	if (printtrunc)
	    fprintf(stderr,"TCP packet %d truncated too short to trace, ignored\n",
		    pnum);
	++ctrunc;
	return(NULL);
    }


    /* convert interesting fields to local byte order */
    th_seq   = ntohl(ptcp->th_seq);
    th_ack   = ntohl(ptcp->th_ack);
    th_sport = ntohs(ptcp->th_sport);
    th_dport = ntohs(ptcp->th_dport);
    th_win   = ntohs(ptcp->th_win);
    ip_len   = ntohs(pip->ip_len);

    /* make sure this is one of the connections we want */
    ptp_save = FindTTP(pip,ptcp,&dir);

    ++packet_count;

    if (ptp_save == NULL) {
	return(NULL);
    }

    ++trace_count;

    /* do time stats */
    if (ptp_save->first_time.tv_sec == 0) {
	ptp_save->first_time = current_time;
    }
    ptp_save->last_time = current_time;


    /* if we're ignoring this connection, do no further processing */
    if (ptp_save->ignore_pair) {
	return(ptp_save);
    }

    /* grab the address from this packet */
    CopyAddr(&tp_in.addr_pair, pip->ip_src, pip->ip_dst,
	     th_sport, th_dport);

    /* figure out which direction this packet is going */
    if (dir == A2B) {
	thisdir  = &ptp_save->a2b;
	otherdir = &ptp_save->b2a;
    } else {
	thisdir  = &ptp_save->b2a;
	otherdir = &ptp_save->a2b;
    }


    /* plotter shorthand */
    to_tsgpl     = otherdir->tsg_plotter;
    from_tsgpl   = thisdir->tsg_plotter;


    /* check the options */
    ptcpo = ParseOptions(ptcp,plast);
    if (ptcpo->mss != -1)
	thisdir->mss = ptcpo->mss;
    if (ptcpo->ws != -1) {
	thisdir->window_scale = ptcpo->ws;
	thisdir->f1323_ws = TRUE;
    }
    if (ptcpo->tsval != -1) {
	thisdir->f1323_ts = TRUE;
    }
    /* NOW, unless BOTH sides asked for window scaling in their SYN	*/
    /* segments, we aren't using window scaling */
    if (!SYN_SET(ptcp) &&
	((!thisdir->f1323_ws) || (!otherdir->f1323_ws))) {
	thisdir->window_scale = otherdir->window_scale = 0;
    }

    /* check sacks */
    if (ptcpo->sack_req) {
	thisdir->fsack_req = 1;
    }
    if (ptcpo->sack_count > 0) {
	++thisdir->sacks_sent;
    }

    /* calculate data length */
    tcp_length = ip_len - (4 * pip->ip_hl);
    tcp_data_length = tcp_length - (4 * ptcp->th_off);

    /* SYN and FIN are really data, too (sortof) */
#ifdef OLD
    /* Mark didn't like this and I can't remember why I did it anyway... */
    if (SYN_SET(ptcp)) ++tcp_data_length;
    if (FIN_SET(ptcp)) ++tcp_data_length;
#endif /* OLD */


    /* do data stats */
    if (tcp_data_length > 0) {
	thisdir->data_pkts += 1;
	thisdir->data_bytes += tcp_data_length;
	if (tcp_data_length > thisdir->max_seg_size)
	    thisdir->max_seg_size = tcp_data_length;
	if ((thisdir->min_seg_size == 0) ||
	    (tcp_data_length < thisdir->min_seg_size))
	    thisdir->min_seg_size = tcp_data_length;
    }

    /* total packets stats */
    ++ptp_save->packets;
    ++thisdir->packets;
    if (SYN_SET(ptcp))
	++thisdir->syn_count;
    if (RESET_SET(ptcp))
	++thisdir->reset_count;
    if (FIN_SET(ptcp))
	++thisdir->fin_count;

    /* instantaneous throughput stats */
    if (graph_tput) {
	DoThru(thisdir,tcp_data_length);
    }

    /* calc. data range */
    start = th_seq;
    end = start + tcp_data_length;

    /* set minimum seq */
    if ((thisdir->min_seq == 0) && (start != 0)) {
	thisdir->min_seq = start;
    }
    thisdir->max_seq = end;

  
    /* save the stream contents, if requested */
    if (save_tcp_data && (tcp_data_length > 0)) {
	u_char *pdata = (u_char *)ptcp + ptcp->th_off*4;
	u_long saved;
	saved = tcp_data_length;
	if ((u_long)pdata + tcp_data_length > ((u_long)plast+1))
	    saved = (u_long)plast - (u_long)pdata + 1;
	ExtractContents(start,tcp_data_length,saved,pdata,thisdir);
    }

    /* record sequence limits */
    if (SYN_SET(ptcp)) {
	thisdir->syn = start;
	otherdir->ack = start;  /* bug fix for Rob Austein <sra@epilogue.com> */
    }
    if (FIN_SET(ptcp)) {
	/* bug fix, if there's data here too, we need to bump up the FIN */
	/* (psc data file shows example) */
	thisdir->fin = start + tcp_data_length;
    }

    /* do rexmit stats */
    retrans = FALSE;
    out_order = FALSE;
    retrans_num_bytes = 0;
    if (tcp_data_length > 0) {
	retrans_num_bytes = rexmit(thisdir,start,tcp_data_length,&out_order);
	if (out_order)
	    ++thisdir->out_order_pkts;
    }


    /* do rtt stats */
    if (ACK_SET(ptcp)) {
	ack_in(otherdir,th_ack);
    }


    /* plot out-of-order segments, if asked */
    if (out_order && (from_tsgpl != NO_PLOTTER) && show_out_order) {
	plotter_perm_color(from_tsgpl, out_order_color);
	plotter_text(from_tsgpl, current_time, end,
		     "a", "O");
	if (bottom_letters)
	    plotter_text(from_tsgpl, current_time, thisdir->min_seq-1500,
			 "c", "O");
/* 	plotter_perm_color(from_tsgpl, default_color); */
    }

    if ((thisdir->time.tv_sec != -1) && (retrans_num_bytes>0)) {
	retrans = TRUE;
	thisdir->rexmit_pkts += 1;
	thisdir->rexmit_bytes += retrans_num_bytes;
	if (from_tsgpl != NO_PLOTTER && show_rexmit) {
	    plotter_perm_color(from_tsgpl, retrans_color);
	    plotter_text(from_tsgpl, current_time, end,
			 "a", "R");
	    if (bottom_letters)
		plotter_text(from_tsgpl, current_time, thisdir->min_seq-1500,
			     "c", "R");
/* 	    plotter_perm_color(from_tsgpl, default_color); */
	}
    } else {
	thisdir->seq = end;
    }


    /* draw the packet */
    if (from_tsgpl != NO_PLOTTER) {
	plotter_perm_color(from_tsgpl, data_color);
	if (SYN_SET(ptcp)) {		/* SYN  */
	    plotter_perm_color(from_tsgpl, synfin_color);
	    plotter_diamond(from_tsgpl, current_time, start);
	    plotter_text(from_tsgpl, current_time, end, "a", "SYN");
	    plotter_uarrow(from_tsgpl, current_time, end);
	    plotter_line(from_tsgpl, current_time, start, current_time, end);
/* 	    plotter_perm_color(from_tsgpl, default_color); */
	} else if (FIN_SET(ptcp)) {	/* FIN  */
	    plotter_perm_color(from_tsgpl, synfin_color);
	    plotter_box(from_tsgpl, current_time, start);
	    plotter_text(from_tsgpl, current_time, end, "a", "FIN");
	    plotter_uarrow(from_tsgpl, current_time, end);
	    plotter_line(from_tsgpl, current_time, start, current_time, end);
/* 	    plotter_perm_color(from_tsgpl, default_color); */
	} else if (tcp_data_length > 0) {		/* DATA */
	    if (retrans)
		plotter_perm_color(from_tsgpl, retrans_color);
	    plotter_darrow(from_tsgpl, current_time, start);
	    if (PUSH_SET(ptcp)) {
		/* colored diamond is PUSH */
		plotter_temp_color(from_tsgpl, push_color);
		plotter_diamond(from_tsgpl, current_time, end);
		plotter_temp_color(from_tsgpl, push_color);
		plotter_dot(from_tsgpl, current_time, end);
	    } else {
		plotter_uarrow(from_tsgpl, current_time, end);
	    }
	    plotter_line(from_tsgpl, current_time, start, current_time, end);
/* 	    if (retrans) */
/* 		plotter_perm_color(from_tsgpl, default_color); */
	}
/* 	plotter_perm_color(from_tsgpl, default_color); */
    }

    /* check for RESET */
    if (RESET_SET(ptcp)) {
	unsigned int plot_at;

	/* if there's an ACK in this packet, plot it there */
	/* otherwise, plot it at the last valid ACK we have */
	if (ACK_SET(ptcp))
	    plot_at = th_ack;
	else
	    plot_at = thisdir->ack;

	if (to_tsgpl != NO_PLOTTER) {
	    plotter_temp_color(to_tsgpl, text_color);
	    plotter_text(to_tsgpl,
			 current_time, plot_at,
			 "a", "RST_IN");
	}
	if (from_tsgpl != NO_PLOTTER) {
	    plotter_temp_color(from_tsgpl, text_color);
	    plotter_text(from_tsgpl,
			 current_time, start,
			 "a", "RST_OUT");
	}
	if (ACK_SET(ptcp))
	    ++thisdir->ack_pkts;
	return(ptp_save);
    }

    
    /* draw the ack and win in the other plotter */
    if (ACK_SET(ptcp)) {
	unsigned int ack = th_ack;
	unsigned int win = th_win << thisdir->window_scale;
	unsigned int winend;

	winend = ack + win;
      
	/* do window stats */
	if (win > thisdir->win_max)
	    thisdir->win_max = win;
	if ((win > 0) &&
	    ((thisdir->win_min == 0) ||
	     (win < thisdir->win_min)))
	    thisdir->win_min = win;
	thisdir->win_tot += win;
	if (win == 0) {
	    ++thisdir->win_zero_ct;
	    if (to_tsgpl != NO_PLOTTER && show_zero_window) {
		plotter_temp_color(to_tsgpl, text_color);
		plotter_text(to_tsgpl,
			     current_time, winend,
			     "a", "Z");
		if (bottom_letters) {
		    plotter_temp_color(to_tsgpl, text_color);
		    plotter_text(to_tsgpl,
				 current_time, otherdir->min_seq-1500,
				 "a", "Z");
		}
	    }
	}

	++thisdir->ack_pkts;

	if (to_tsgpl != NO_PLOTTER && thisdir->time.tv_sec != -1) {
	    plotter_perm_color(to_tsgpl, ack_color);
	    plotter_line(to_tsgpl, thisdir->time,
			 thisdir->ack, current_time, thisdir->ack);
	    if (thisdir->ack != ack) {
		plotter_line(to_tsgpl, current_time, thisdir->ack, current_time, ack);
	    } else {
		plotter_dtick(to_tsgpl, current_time, ack);
	    }
	    plotter_perm_color(to_tsgpl, window_color);
	    plotter_line(to_tsgpl,
			 thisdir->time, thisdir->windowend,
			 current_time, thisdir->windowend);
	    if (thisdir->windowend != winend) {
		plotter_line(to_tsgpl,
			     current_time, thisdir->windowend,
			     current_time, winend);
	    } else {
		plotter_utick(to_tsgpl, current_time, winend);
	    }
/* 	    plotter_perm_color(to_tsgpl, default_color); */
	}

	/* draw sacks, if appropriate */
	if (to_tsgpl != NO_PLOTTER && show_sacks
	    && (ptcpo->sack_count > 0)) {
	    int scount;
	    for (scount = 0; scount < ptcpo->sack_count; ++scount) {
		plotter_perm_color(to_tsgpl, sack_color);
		plotter_line(to_tsgpl,
			     current_time, ptcpo->sacks[scount].sack_left,
			     current_time, ptcpo->sacks[scount].sack_right);
		plotter_text(to_tsgpl, current_time,
			     ptcpo->sacks[scount].sack_right,
			     "a", "S");  /* 'S' is for Sack */
/* 		plotter_perm_color(to_tsgpl, default_color); */
	    }
	}
	thisdir->time = current_time;
	thisdir->ack = ack;
	thisdir->windowend = winend;
    }  /* end ACK_SET(ptcp) */

    /* do stats for initial window (first slow start) */
    /* (if there's data in this and we've NEVER seen */
    /*  an ACK coming back from the other side) */
    /* this is for Mark Allman for slow start testing -- Mon Mar 10, 1997 */
    if (!otherdir->data_acked && ACK_SET(ptcp)
	&& ((otherdir->syn+1) != th_ack)) {
	otherdir->data_acked = TRUE;
    }
    if ((tcp_data_length > 0) && (!thisdir->data_acked)) {
	if (!retrans) {
	    /* don't count it if it was retransmitted */
	    thisdir->initialwin_bytes += tcp_data_length;
	    thisdir->initialwin_segs += 1;
	}
    }

    /* do stats for congestion window (estimated) */
    /* estimate the congestion window as the number of outstanding */
    /* un-acked bytes */
    if (!SYN_SET(ptcp) && !out_order && !retrans) {
	u_long cwin = end - otherdir->ack;

	if (cwin > thisdir->cwin_max)
	    thisdir->cwin_max = cwin;
	if ((cwin > 0) &&
	    ((thisdir->cwin_min == 0) ||
	     (cwin < thisdir->cwin_min)))
	    thisdir->cwin_min = cwin;
	thisdir->cwin_tot += cwin;
    }

    return(ptp_save);
}



void
trace_done(void)
{
    tcp_pair *ptp;
    int ix;

    if (trace_count == 0) {
	fprintf(stdout,"no traced packets\n");
	return;
    }

    if (!printbrief)
	fprintf(stdout,"%d %s traced:\n",
		num_tcp_pairs + 1,
		num_tcp_pairs==0?"connection":"connections");
    fprintf(stdout,"%d packets seen, %d TCP packets traced\n",
	    packet_count, trace_count);
    if (ctrunc > 0) {
	fprintf(stdout,"*** %d packets were too short to process at some point\n",
		ctrunc);
	if (!printtrunc)
	    fprintf(stdout,"\t(use -w option to show details)\n");
    }
    if (debug>1)
	fprintf(stdout,"average search length: %d\n",
		search_count / packet_count);
    for (ix = 0; ix <= num_tcp_pairs; ++ix) {
	ptp = ttp[ix];
	if (!ptp->ignore_pair) {
	    if (printbrief) {
		fprintf(stdout,"%3d: ", ix+1);
		PrintBrief(ptp);
	    } else if (!ignore_non_comp || ConnComplete(ptp)) {
		if (ix > 0)
		    fprintf(stdout,"================================\n");
		fprintf(stdout,"connection %d:\n", ix+1);
		PrintTrace(ptp);
	    }
	}
    }

    if ((debug>1) && !nonames)
	cadump();
}

static void
MoreTcpPairs(
    int num_needed)
{
    int new_max_tcp_pairs;
    int i;

    if (num_needed < max_tcp_pairs)
	return;

    new_max_tcp_pairs = max_tcp_pairs * 4;
    while (new_max_tcp_pairs < num_needed)
	new_max_tcp_pairs *= 4;
    
    if (debug)
	printf("trace: making more space for %d total TCP pairs\n",
	       new_max_tcp_pairs);

    /* enlarge array to hold any pairs that we might create */
    ttp = ReallocZ(ttp,
		   max_tcp_pairs * sizeof(tcp_pair *),
		   new_max_tcp_pairs * sizeof(tcp_pair *));

    /* enlarge array to keep track of which ones to ignore */
    ignore_pairs = ReallocZ(ignore_pairs,
			    max_tcp_pairs * sizeof(Bool),
			    new_max_tcp_pairs * sizeof(Bool));
    if (more_conns_ignored)
	for (i=max_tcp_pairs; i < new_max_tcp_pairs;++i)
	    ignore_pairs[i] = TRUE;

    max_tcp_pairs = new_max_tcp_pairs;
}


void
trace_init(void)
{
    static Bool initted = FALSE;

    if (initted)
	return;

    initted = TRUE;

    /* create an array to hold any pairs that we might create */
    ttp = (tcp_pair **) MallocZ(max_tcp_pairs * sizeof(tcp_pair *));

    /* create an array to keep track of which ones to ignore */
    ignore_pairs = (Bool *) MallocZ(max_tcp_pairs * sizeof(Bool));

    cainit();
    Minit();
}


void
IgnoreConn(
    int ix)
{
    if (debug) fprintf(stderr,"ignoring conn %d\n", ix);

    trace_init();
	
    --ix;

    MoreTcpPairs(ix);

    more_conns_ignored = FALSE;
    ignore_pairs[ix] = TRUE;
}


void
OnlyConn(
    int ix_only)
{
    int ix;
    static Bool cleared = FALSE;
	
    if (debug) fprintf(stderr,"only printing conn %d\n", ix_only);

    trace_init();
	
    --ix_only;

    MoreTcpPairs(ix_only);

    if (!cleared) {
	for (ix = 0; ix < max_tcp_pairs; ++ix) {
	    ignore_pairs[ix] = TRUE;
	}
	cleared = TRUE;
    }

    more_conns_ignored = TRUE;
    ignore_pairs[ix_only] = FALSE;
}


/* get a long (4 byte) option (to avoid address alignment problems) */
static u_long
get_long_opt(
    void *ptr)
{
    u_long l;
    memcpy(&l,ptr,sizeof(u_long));
    return(l);
}


/* get a short (2 byte) option (to avoid address alignment problems) */
static u_short
get_short_opt(
    void *ptr)
{
    u_short s;
    memcpy(&s,ptr,sizeof(u_short));
    return(s);
}


struct tcp_options *
ParseOptions(
    struct tcphdr *ptcp,
    void *plast)
{
    static struct tcp_options tcpo;
    struct sack_block *psack;
    u_char *pdata;
    u_char *popt;
    u_char *plen;

    popt  = (u_char *)ptcp + sizeof(struct tcphdr);
    pdata = (u_char *)ptcp + ptcp->th_off*4;

    tcpo.mss = tcpo.ws = tcpo.tsval = tcpo.tsecr = -1;
    tcpo.sack_req = 0;
    tcpo.sack_count = -1;

    while (popt < pdata) {
	plen = popt+1;

	/* check for truncation error */
	if ((unsigned)popt > (unsigned)plast) {
	    if (printtrunc)
		fprintf(stderr,"\
ParseOptions: packet %d too short to parse remaining options\n", pnum);
	    ++ctrunc;
	    break;
	}

#define CHECK_O_LEN(opt) \
	if (*plen == 0) { fprintf(stderr, "\
ParseOptions: packet %d %s option has length 0, skipping other options\n", \
              pnum,opt); \
	      popt = pdata; break;} \
	if ((unsigned)popt > (unsigned)(plast)) { \
	    if (printtrunc) \
		fprintf(stderr, "\
ParseOptions: packet %d %s option cut short by snap length, skipping other options\n", \
              pnum,opt); \
	      ++ctrunc; \
	      popt = pdata; break;} \


	switch (*popt) {
	  case TCPOPT_EOL: ++popt; break;
	  case TCPOPT_NOP: ++popt; break;
	  case TCPOPT_MAXSEG:
	    CHECK_O_LEN("TCPOPT_MAXSEG");
	    tcpo.mss = ntohs(get_short_opt(popt+2));
	    popt += *plen;
	    break;
	  case TCPOPT_WS:
	    CHECK_O_LEN("TCPOPT_WS");
	    tcpo.ws = *((u_char *)(popt+2));
	    popt += *plen;
	    break;
	  case TCPOPT_TS:
	    CHECK_O_LEN("TCPOPT_TS");
	    tcpo.tsval = ntohl(get_long_opt(popt+2));
	    tcpo.tsecr = ntohl(get_long_opt(popt+6));
	    popt += *plen;
	    break;
	  case TCPOPT_SACK_PERM:
	    CHECK_O_LEN("TCPOPT_SACK_PERM");
	    tcpo.sack_req = 1;
	    popt += *plen;
	    break;
	  case TCPOPT_SACK:
	    /* see which bytes are acked */
	    CHECK_O_LEN("TCPOPT_SACK");
	    tcpo.sack_count = 0;
	    psack = (sack_block *)(popt+2);  /* past the kind and length */
	    popt += *plen;
	    while ((unsigned)psack < (unsigned)popt) {
		/* warning, possible alignment problem here, so we'll
		   use memcpy() and hope for the best */
		/* better use -fno-builtin to avoid gcc alignment error
		   in GCC 2.7.2 */
		memcpy(&tcpo.sacks[(unsigned)tcpo.sack_count], psack,
		       sizeof(sack_block));
		++psack;
		if ((unsigned)psack > ((unsigned)plast+1)) {
		    /* this SACK block isn't all here */
		    if (printtrunc)
			fprintf(stderr,
				"packet %d: SACK block truncated, ignoring the rest\n",
				pnum);
		    ++ctrunc;
		    break;
		}
		++tcpo.sack_count;
		if (tcpo.sack_count > MAX_SACKS) {
		    /* this isn't supposed to be able to happen */
		    fprintf(stderr,
			    "Warning, internal error, too many sacks!!\n");
		    tcpo.sack_count = MAX_SACKS;
		}
	    }
	    break;
	  default:
	    if (debug)
		fprintf(stderr,
			"Warning, ignoring unknown TCP option 0x%x\n",
			*popt);
	    CHECK_O_LEN("TCPOPT_UNKNOWN");
	    popt += *plen;
	    break;
	}
    }

    return(&tcpo);
}



static void
ExtractContents(
    u_long seq,
    u_long tcp_data_bytes,
    u_long saved_data_bytes,
    void *pdata,
    tcb *ptcb)
{
    u_long missing;
    long offset;
    u_long fptr;
    static char filename[15];

    if (saved_data_bytes == 0)
	return;

    /* if we haven't (didn't) seen the SYN, then can't do this!! */
    if (ptcb->syn_count == 0) {
	if (debug>1)
	    fprintf(stderr,"ExtractContents: skipping data, didn't see SYN\n");
	return;
    }
    
    /* how many bytes do we have? */
    missing = tcp_data_bytes - saved_data_bytes;
    if (debug > 2)
	fprintf(stderr,"ExtractContents: missing %ld bytes (%ld-%ld)\n",
	       missing,tcp_data_bytes,saved_data_bytes);
    if (missing > 0) {
	ptcb->trunc_bytes += missing;
	++ptcb->trunc_segs;
    }

    
    /* if the FILE is "-1", couldn't open file */
    if (ptcb->extracted_contents_file == (MFILE *) -1) {
	return;
    }

    /* if the FILE is NULL, open file */
    sprintf(filename,"%s2%s%s", ptcb->host_letter, ptcb->ptwin->host_letter,
	    CONTENTS_FILE_EXTENSION);
    if (ptcb->extracted_contents_file == (MFILE *) NULL) {
	MFILE *f;

	if ((f = Mfopen(filename,"w")) == NULL) {
	    perror(filename);
	    ptcb->extracted_contents_file = (MFILE *) -1;
	}

	if (debug)
	    fprintf(stderr,"TCP contents file is '%s'\n", filename);

	ptcb->extracted_contents_file = f;

	/* beginning of the file is this sequence number */
	ptcb->extr_lastseq = seq;
	
    }

    /* see where we should start writing */
    /* a little complicated, because we want to support really long files */
    offset = SEQCMP(seq,ptcb->extr_lastseq);
    

    /* seek to the correct place in the file */
    if (Mfseek(ptcb->extracted_contents_file, offset, SEEK_CUR) == -1) {
	perror("fseek");
	exit(-1);
    }

    /* see where we are */
    fptr = Mftell(ptcb->extracted_contents_file);

    if (debug>1)
	fprintf(stderr,"Saving %ld bytes from stream '%s2%s' at offset %ld in file '%s'\n",
		saved_data_bytes,
		ptcb->host_letter, ptcb->ptwin->host_letter,
		fptr, filename);

    /* store the bytes */
    if (Mfwrite(pdata,1,saved_data_bytes,ptcb->extracted_contents_file)
	!= saved_data_bytes) {
	perror("fwrite");
	exit(-1);
    }

    /* go back to where we started to not confuse the next write */
    ptcb->extr_lastseq = seq;
    if (Mfseek(ptcb->extracted_contents_file, fptr, SEEK_SET) == -1) {
	perror("fseek 2");
	exit(-1);
    }
}
