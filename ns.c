/*
 * Kevin Lahey (kml@novell.com)
 * Novell, Inc.
 */

static char const rcsid[] =
    "@(#)$Header: /home/sdo/src/tcptrace/src/RCS/ns.c,v 1.2 1999/06/23 19:30:50 sdo Exp $";


/* 
 * ns.c - ns specific file reading stuff
 */


#include "tcptrace.h"

#ifdef GROK_NS


/* static buffers for reading */
static struct ether_header *pep;
static int *pip_buf;
static struct ip *ipb;
static struct tcphdr *tcpb;

/* for debugging */
static unsigned linenum;

/* return the next packet header */
/* currently only works for ETHERNET */
static int
pread_ns(
    struct timeval	*ptime,
    int		 	*plen,
    int		 	*ptlen,
    void		**pphys,
    int			*pphystype,
    struct ip		**ppip,
    void		**pplast)
{
    static int packlen = 0;
    double c, d, e;

    while (1) {
	/* read the packet info */

	char tt;
	double timestamp;
	int junk;
	char type[100];
	char flags[100];
	int iteration;
	int seq;
	int is_ack;
	int is_tcp;
	int rlen;

	++linenum;

	/* correct NS output line would have 14 fields: */
	rlen = fscanf(stdin, "%c %lg %d %d %s %d %s %d %d.%hu %d.%hu %d %hu\n",
		      &tt,
		      &timestamp,
		      &junk,
		      &junk,
		      type,
		      plen,
		      flags,
		      &iteration,
		      &ipb->ip_src.s_addr,
		      &tcpb->th_sport,
		      &ipb->ip_dst.s_addr,
		      &tcpb->th_dport,
		      &seq,
		      &ipb->ip_id);

	/* if we can't match all 14 fields, we give up on the file */
	if (rlen != 14) {
	    fprintf(stderr,"Bad ns packet header in line %u\n", linenum);
	    return(0);
	}

	if (rlen == EOF) {
	    return(0);
	}

	tcpb->th_sport = tcpb->th_dport = iteration;

	is_tcp = strcmp(type, "tcp") == 0;
	is_ack = strcmp(type, "ack") == 0;

	/* if it's not a TCP data segment or ACK, discard and try again */
	if (!is_tcp && !is_ack)
	    continue;

	if (packlen == 0 && is_tcp)
	    packlen = *plen - sizeof(struct ip) - sizeof(struct tcphdr);

	ipb->ip_len = htons(*plen);

	if (is_tcp) {
	    tcpb->th_seq = htonl(packlen * seq);
	    tcpb->th_ack = 0;
	} else {
	    tcpb->th_seq = 0;
	    tcpb->th_ack = htonl(packlen * seq);
	}

	/* make up a reasonable IPv4 packet header */
	ipb->ip_hl = 5; /* no options, normal length of 20 */
	ipb->ip_v = 4;  /* IPv4 */
	ipb->ip_tos = 0;
	ipb->ip_off = 0;
	ipb->ip_ttl = 64;  /* nice round number */
	ipb->ip_p = 6;     /* TCP */
	ipb->ip_sum = 0;   /* IP checksum, hope it doesn't get checked! */
	ipb->ip_id = htons(ipb->ip_id);

	/* is the transport "ECN-Capable"? */
	if (strchr(flags, 'N') != NULL)
	    ipb->ip_tos |= IPTOS_ECT;

	/* was the "Experienced Congestion" bit set? */
	if (strchr(flags, 'E') != NULL)
	    ipb->ip_tos |= IPTOS_CE;

	/* make up a reasonable TCP segment header */
	tcpb->th_off = 5;  /* no options, normal length of 20 */
	tcpb->th_flags = TH_ACK; /* sdo: what about first SYN?? */
	tcpb->th_x2 = 0;
	tcpb->th_sum = 0;
	tcpb->th_urp = 0;
	tcpb->th_win = htons(65535);

	/* x2 *was* reserved, now used for ECN bits */

	if (strchr(flags, 'C') != NULL)
	    tcpb->th_x2 |= TH_ECN_ECHO;
	if (strchr(flags, 'A') != NULL)
	    tcpb->th_x2 |= TH_CWR;

	/* convert floating point timestamp to (tv_sec,tv_usec) */
	c = floor(timestamp);
	ptime->tv_sec  = c;
	d = timestamp - (double) ptime->tv_sec;
	e = d * 1000000.0;
	ptime->tv_usec = e;

	*ptlen         = *plen;

	*ppip  = (struct ip *) pip_buf;
	*pplast = (char *)pip_buf + *plen;
	*pphys  = pep;
	*pphystype = PHYS_ETHER;

/*
  printf("timestamp %g, type %s, plen %d, seq %d, id %d\n",
  timestamp, type, *plen, seq, ipb->ip_id);
*/

	return(1);
    }
}



/*
 * is_ns()   is the input file in ns format??
 */
pread_f *is_ns(void)
{
    int rlen;

    if ((rlen = getc(stdin)) == EOF) {
	rewind(stdin);
	return(NULL);
    }

    rewind(stdin);

    switch (rlen) {
      case '+':
      case '-':
      case 'h':
      case 'r':
      case 'd':
	break;
      default:
	return(NULL);
    }

    /* OK, it's mine.  Init some stuff */
    pep = MallocZ(sizeof(struct ether_header));
    pip_buf = MallocZ(IP_MAXPACKET);
    
    ipb = (struct ip *) pip_buf;
    tcpb = (struct tcphdr *) (ipb + 1);

    /* Set up the stuff that shouldn't change */
    pep->ether_type = ETHERTYPE_IP;

    /* init line count (we might be called several times, must be done here) */
    linenum = 0;

    return(pread_ns);
}
#endif /* GROK_NS */
