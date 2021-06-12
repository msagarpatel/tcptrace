/*
 * Copyright (c) 1994, 1995, 1996, 1997, 1998, 1999
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
    "@(#)Copyright (c) 1999 -- Shawn Ostermann -- Ohio University.  All rights reserved.\n";
static char const rcsid[] =
    "@(#)$Header: /home/sdo/src/tcptrace/src/RCS/print.c,v 5.10 1999/09/07 22:40:15 sdo Exp $";


/* 
 * print.c -- packet printing routines
 */

#include "tcptrace.h"


/* local routines */
static void printeth_packet(struct ether_header *);
static void printip_packet(struct ip *, void *plast);
static void printtcp_packet(struct ip *, void *plast);
static void printudp_packet(struct ip *, void *plast);
static char *ParenServiceName(portnum);
static char *ParenHostName(struct ipaddr addr);
static void printipv4(struct ip *pip, void *plast);
static void printipv6(struct ipv6 *pipv6, void *plast);
static char *ipv6addr2str(struct in6_addr addr);
static void printipv4_opt_addrs(char *popt, int ptr, int len);



/* Unix format: "Fri Sep 13 00:00:00 1986\n" */
/*			   1         2          */
/*		 012345678901234567890123456789 */
char *
ts2ascii(
    struct timeval	*ptime)
{
	static char buf[30];
	struct tm *ptm;
	char *now;
	int decimal;

	if (ZERO_TIME(ptime))
	    return("        <the epoch>       ");

	ptm = localtime(&ptime->tv_sec);
	now = asctime(ptm);

	/* splice in the microseconds */
	now[19] = '\00';
/* 	decimal = (ptime->tv_usec + 50) / 100;*/  /* for 4 digits */
	decimal = ptime->tv_usec;  /* for 6 digits */

	now[24] = '\00';	/* nuke the newline */
	sprintf(buf, "%s.%06d %s", now, decimal, &now[20]);

	return(buf);
}

/* same as ts2ascii, but leave the year on */
char *
ts2ascii_date(
    struct timeval	*ptime)
{
	static char buf[30];
	struct tm *ptm;
	char *now;
	int decimal;

	if (ZERO_TIME(ptime))
	    return("        <the epoch>       ");

	ptm = localtime(&ptime->tv_sec);
	now = asctime(ptm);
	now[24] = '\00';

/* 	decimal = (ptime->tv_usec + 50) / 100;*/  /* for 4 digits */
	decimal = ptime->tv_usec;  /* for 6 digits */
	sprintf(buf, "%s.%06d", now, decimal);

	return(buf);
}


static void
printeth_packet(
    struct ether_header *pep)
{
    printf("\tETH Srce: %s\n", ether_ntoa((struct ether_addr *)&pep->ether_shost));
    printf("\tETH Dest: %s\n", ether_ntoa((struct ether_addr *)&pep->ether_dhost));

    printf(
	hex?"\t    Type: 0x%x %s\n":"\t    Type: %d %s\n",
	ntohs(pep->ether_type),
	(ntohs(pep->ether_type) == ETHERTYPE_IP)?"(IP)":
	(ntohs(pep->ether_type) == ETHERTYPE_IPV6)?"(IPv6)":
	(ntohs(pep->ether_type) == ETHERTYPE_ARP)?"(ARP)":
	(ntohs(pep->ether_type) == ETHERTYPE_REVARP)?"(RARP)":
	"");
}


static void
printip_packet(
    struct ip *pip,
    void *plast)
{
    /* print an ipv6 header */
    if (PIP_ISV6(pip)) {
	if ((unsigned)pip+sizeof(struct ipv6)-1 > (unsigned)plast) {
	    if (warn_printtrunc)
		printf("\t[packet truncated too short for IP details]\n");
	    ++ctrunc;
	    return;
	}
	printipv6((struct ipv6 *)pip, plast);
	return;
    }

    if (PIP_ISV4(pip)) {
	/* make sure we have enough of the packet */
	if ((unsigned)pip+sizeof(struct ip)-1 > (unsigned)plast) {
	    if (warn_printtrunc)
		printf("\t[packet truncated too short for IP details]\n");
	    ++ctrunc;
	    return;
	}
	printipv4(pip, plast);
	return;
    }

    /* unknown type */
    printf("Unknown IP version %d\n", pip->ip_v);
}



static void
printipv4(
    struct ip *pip,
    void *plast)
{
    u_short offset;
    Bool mf;
    
    /* make sure we have enough of the packet */
    if ((unsigned)pip+sizeof(struct ip)-1 > (unsigned)plast) {
	if (warn_printtrunc)
	    printf("\t[packet truncated too short for IP details]\n");
	++ctrunc;
	return;
    }

    printf("\tIP  VERS: %d\n", pip->ip_v);
    printf("\tIP  Srce: %s %s\n",
	   inet_ntoa(pip->ip_src),
	   ParenHostName(*IPV4ADDR2ADDR(&pip->ip_src)));
    printf("\tIP  Dest: %s %s\n",
	   inet_ntoa(pip->ip_dst),
	   ParenHostName(*IPV4ADDR2ADDR(&pip->ip_dst)));

    printf(
	hex?"\t    Type: 0x%x %s\n":"\t    Type: %d %s\n",
	pip->ip_p, 
	(pip->ip_p == IPPROTO_UDP)?"(UDP)":
	(pip->ip_p == IPPROTO_TCP)?"(TCP)":
	(pip->ip_p == IPPROTO_ICMP)?"(ICMP)":
	(pip->ip_p == IPPROTO_IGMP)?"(IGMP)":
	(pip->ip_p == IPPROTO_EGP)?"(EGP)":
	"");

    printf("\t    HLEN: %d\n", pip->ip_hl*4);
    printf("\t     TTL: %d\n", pip->ip_ttl);
    printf("\t     LEN: %d\n", ntohs(pip->ip_len));
    printf("\t      ID: %d\n", ntohs(pip->ip_id));
    printf("\t   CKSUM: 0x%04x", ntohs(pip->ip_sum));
    if (verify_checksums)
	printf(" (%s)", ip_cksum_valid(pip,plast)?"CORRECT":"WRONG");
    printf("\n");

    /* fragmentation stuff */
    offset = ntohs(pip->ip_off) << 3;
    mf = (ntohs(pip->ip_off) & IP_MF) != 0;
    if ((offset == 0) && (!mf)) {
	printf("\t  OFFSET: 0x%04x", ntohs(pip->ip_off));
    } else {
	printf("\t  OFFSET: 0x%04x (frag: %d bytes at offset %u - %s)",
	       ntohs(pip->ip_off),
	       ntohs(pip->ip_len)-pip->ip_hl*4,
	       offset,
	       mf?"More Frags":"Last Frag");
    }
    if ((ntohs(pip->ip_off) & IP_DF) != 0)
	printf("  Don't Fragment\n");	/* don't fragment */

    /* print IP options if there are any */
    if (pip->ip_hl != 5) {
	char *popt = (char *)pip + 20;
	void *plast_option;

	/* find the last option in the file */
	plast_option = (char *)pip+4*pip->ip_hl-1;
	if (plast_option > plast)
	    plast_option = plast; /* truncated shorter than that */

	printf("\t Options: %d bytes\n", 4*pip->ip_hl-20);
	while ((void *)popt <= plast_option) {
	    u_int opt = *popt;
	    u_int len = *(popt+1);
	    u_int ptr = *(popt+2);
	    int optcopy = (opt&0x80);
	    int optclass = (opt&0x60)>>5;
	    int optnum = (opt&0x1f);

	    /* check for truncated option */
	    if ((void *)(popt+len-1) > plast) {
		printf("\t    IP option (truncated)\n");
		continue;
	    }

	    printf("\t    IP option %d (copy:%c  class:%s  number:%d)\n",
		   opt,
		   optcopy==0?'N':'Y',
		   optclass==0?"ctrl":
		   optclass==1?"reserved1":
		   optclass==2?"debug":
		   optclass==3?"reserved3":"unknown",
		   optnum);


	    switch(opt) {
	      case 3:
		printf("\t      Loose source route:  len: %d  ptr:%d\n",
		       len, ptr);
		printipv4_opt_addrs(popt, ptr, len);
		break;
	      case 7:
		printf("\t      Record Route:  len: %d  ptr:%d\n",
		       len, ptr);
		printipv4_opt_addrs(popt, ptr, len);
		break;
	      case 9:
		printf("\t      Strict source route:  len: %d  ptr:%d\n",
		       len, ptr);
		printipv4_opt_addrs(popt, ptr, len);
		break;
	      case 4:
		printf("\t      Timestamps:  len: %d  ptr:%d\n",
		       len, ptr);
		break;
	      case 0:
		printf("\t      EOL\n");
		len = 1;
		break;
	      case 1:
		printf("\t      PADDING\n");
		len = 1;
		break;
	      default:
		printf("\t      Unknown Option %d, len: %d\n", opt, len);
		break;
	    }
	    if (len <= 0)
		break;
	    popt += len;
	}
    }

    printf("\n");
}


/* print out the little table in the source route and record route options */
static void
printipv4_opt_addrs(
    char *popt,
    int ptr,
    int len)
{
    struct in_addr ina;
    int nptr;
    int i;

    for (nptr=4,i=1;nptr < len; nptr += 4,++i) {
	memcpy(&ina.s_addr,popt+nptr-1,4);
	if (nptr < ptr)
	    printf("\t        %d: %-15s  %s\n",
		   i, inet_ntoa(ina),
		   HostName(*IPV4ADDR2ADDR(&ina)));
	else
	    printf("\t        %d: xxxxxxxxxxx\n", i);
    }
}


static void
printtcp_packet(
    struct ip *pip,
    void *plast)
{
    unsigned tcp_length;
    unsigned tcp_data_length;
    struct tcphdr *ptcp;
    int i;
    u_char *pdata;
    struct ipv6 *pipv6;

    /* find the tcp header */
    ptcp = gettcp(pip, &plast);
    if (ptcp == NULL)
	return;			/* not TCP */

    /* make sure we have enough of the packet */
    if ((unsigned)ptcp+sizeof(struct tcphdr)-1 > (unsigned)plast) {
	if (warn_printtrunc)
	    printf("\t[packet truncated too short for TCP details]\n");
	++ctrunc;
	return;
    }

    /* calculate data length */
    if (PIP_ISV6(pip)) {
	pipv6 = (struct ipv6 *) pip;
	tcp_length = ntohs(pipv6->ip6_lngth);
    } else {
	tcp_length = ntohs(pip->ip_len) - (4 * pip->ip_hl);
    }
    tcp_data_length = tcp_length - (4 * ptcp->th_off);

    printf("\tTCP SPRT: %u %s\n",
	   ntohs(ptcp->th_sport),
	   ParenServiceName(ntohs(ptcp->th_sport)));
    printf("\t    DPRT: %u %s\n",
	   ntohs(ptcp->th_dport),
	   ParenServiceName(ntohs(ptcp->th_dport)));
    printf("\t     FLG: %c%c%c%c%c%c%c%c (0x%02x)\n",
	   FLAG6_SET(ptcp)? '?':' ',
	   FLAG7_SET(ptcp)? '?':' ',
	   URGENT_SET(ptcp)?'U':'-',
	   ACK_SET(ptcp)?   'A':'-',
	   PUSH_SET(ptcp)?  'P':'-',
	   RESET_SET(ptcp)? 'R':'-',
	   SYN_SET(ptcp)?   'S':'-',
	   FIN_SET(ptcp)?   'F':'-',
	   ptcp->th_flags);
    printf(
	hex?"\t     SEQ: 0x%08x\n":"\t     SEQ: %d\n",
	ntohl(ptcp->th_seq));
    printf(
	hex?"\t     ACK: 0x%08x\n":"\t     ACK: %d\n",
	ntohl(ptcp->th_ack));
    printf("\t     WIN: %u\n", ntohs(ptcp->th_win));
    printf("\t    HLEN: %u", ptcp->th_off*4);
    if ((u_long)ptcp + ptcp->th_off*4 - 1 > (u_long)plast) {
	/* not all there */
	printf(" (only %ld bytes in dump file)",
	       (u_long)plast - (u_long)ptcp + 1);
    }
    printf("\n");
    
    if (ptcp->th_x2 != 0) {
	printf("\t    MBZ: 0x%01x (these are supposed to be zero!)\n",
	       ptcp->th_x2);
    }
    printf("\t   CKSUM: 0x%04x", ntohs(ptcp->th_sum));
    pdata = (u_char *)ptcp + ptcp->th_off*4;
    if (verify_checksums) {
	if ((u_long)pdata + tcp_data_length > ((u_long)plast+1))
	    printf(" (too short to verify)");
	else
	    printf(" (%s)", tcp_cksum_valid(pip,ptcp,plast)?"CORRECT":"WRONG");
    }
    printf("\n");


    printf("\t    DLEN: %u", tcp_data_length);
    if ((tcp_data_length != 0) &&
	((u_long)pdata + tcp_data_length > ((u_long)plast+1))) {
	int available =  (u_long)plast - (u_long)pdata + 1;
	if (available > 1)
	    printf(" (only %ld bytes in dump file)",
		   (u_long)plast - (u_long)pdata + 1);
	else
	    printf(" (none of it in dump file)");
    }
    printf("\n");
    if (ptcp->th_off != 5) {
	struct tcp_options *ptcpo;

        printf("\t    OPTS: %u bytes",
	       (ptcp->th_off*4) - sizeof(struct tcphdr));
	if ((u_long)ptcp + ptcp->th_off*4 - 1 > (u_long)plast) {
	    /* not all opts were stored */
	    u_long available = 1 + (u_long)plast -
		((u_long)ptcp + sizeof(struct tcphdr));
	    if (available > 1)
		printf(" (%lu bytes in file)", available);
	    else
		printf(" (none of it in dump file)");
	}

	printf("\t");

	ptcpo = ParseOptions(ptcp,plast);

	if (ptcpo->mss != -1)
	    printf(" MSS(%d)", ptcpo->mss);
	if (ptcpo->ws != -1)
	    printf(" WS(%d)", ptcpo->ws);
	if (ptcpo->tsval != -1) {
	    printf(" TS(%ld,%ld)", ptcpo->tsval, ptcpo->tsecr);
	}
	if (ptcpo->sack_req) {
	    printf(" SACKREQ");
	}
	if (ptcpo->sack_count >= 0) {
	    printf(" SACKS(%d)", ptcpo->sack_count);
	    for (i=0; i < ptcpo->sack_count; ++i) {
		printf("[0x%08lx-0x%08lx]",
		       ptcpo->sacks[i].sack_left,
		       ptcpo->sacks[i].sack_right);
	    }
	}
	if (ptcpo->echo_req != -1)
	    printf(" ECHO(%lu)", ptcpo->echo_req);
	if (ptcpo->echo_repl != -1)
	    printf(" ECHOREPL(%lu)", ptcpo->echo_repl);
	if (ptcpo->cc != -1)
	    printf(" CC(%lu)", ptcpo->cc);
	if (ptcpo->ccnew != -1)
	    printf(" CCNEW(%lu)", ptcpo->ccnew);
	if (ptcpo->ccecho != -1)
	    printf(" CCECHO(%lu)", ptcpo->ccecho);
	for (i=0; i < ptcpo->unknown_count; ++i) {
	    if (i < MAX_UNKNOWN) {
		printf(" UNKN(op:%d,len:%d)",
		       ptcpo->unknowns[i].unkn_opt,
		       ptcpo->unknowns[i].unkn_len);
	    } else {
		printf("... more unsaved unknowns\n");
		break;
	    }
	}
        printf("\n");
    }
    if (tcp_data_length > 0) {
	if (dump_packet_data) {
	    char *ptcp_data = (char *)ptcp + (4 * ptcp->th_off);
	    PrintRawData("   data", ptcp_data, plast, TRUE);
	} else {
	    printf("\t    data: %u bytes\n", tcp_data_length);
	}
    }
}


static void
printudp_packet(
    struct ip *pip,
    void *plast)
{
    struct udphdr *pudp;
    u_char *pdata;

    /* find the udp header */
    pudp = getudp(pip, &plast);
    if (pudp == NULL)
	return;			/* not UDP */

    /* make sure we have enough of the packet */
    if ((unsigned)pudp+sizeof(struct udphdr)-1 > (unsigned)plast) {
	if (warn_printtrunc)
	    printf("\t[packet truncated too short for UDP details]\n");
	++ctrunc;
	return;
    }

    printf("\tUDP SPRT: %u %s\n",
	   ntohs(pudp->uh_sport),
	   ParenServiceName(ntohs(pudp->uh_sport)));
    printf("\t    DPRT: %u %s\n",
	   ntohs(pudp->uh_dport),
	   ParenServiceName(ntohs(pudp->uh_dport)));
    pdata = (u_char *)pudp + sizeof(struct udphdr);
    printf("\t    DLEN: %u", ntohs(pudp->uh_ulen));
    if ((u_long)pdata + ntohs(pudp->uh_ulen) > ((u_long)plast+1))
	printf(" (only %ld bytes in dump file)\n",
	       (u_long)plast - (u_long)pdata + 1);
    if (ntohs(pudp->uh_ulen) > 0) {
	if (dump_packet_data)
	    PrintRawData("   data", pdata, plast, TRUE);
    }
}



void
printpacket(
     int		len,
     int		tlen,
     void		*phys,
     int		phystype,
     struct ip		*pip,
     void 		*plast)
{
    if (len == 0)
	/* original length unknown */
        printf("\tSaved Length: %d\n", tlen);
    else if (len == tlen)
        printf("\tPacket Length: %d\n", len);
    else
        printf("\tPacket Length: %d (saved length %d)\n", len,tlen);

    printf("\tCollected: %s\n", ts2ascii(&current_time));

    if (phys) {
	switch(phystype) {
	  case PHYS_ETHER:
	    printeth_packet(phys);
	    break;
	  default:
	    printf("\tPhysical layer: %d (not understood)\n", phystype);
	    break;
	}
    }

    /* it's always supposed to be an IP packet */
    printip_packet(pip,plast);


    /* this will fail if it's not TCP */
    printtcp_packet(pip,plast);

    /* this will fail if it's not UDP */
    printudp_packet(pip,plast);
}


static char *
ParenServiceName(
     portnum port)
{
    char *pname;
    static char buf[80];

    pname = ServiceName(port);
    if (!pname || isdigit((int)(*pname)))
	return("");

    sprintf(buf,"(%s)",pname);
    return(buf);
}


static char *
ParenHostName(
     struct ipaddr addr)
{
    char *pname;
    static char buf[80];

    pname = HostName(addr);
    if (!pname || isdigit((int)(*pname)))
	return("");

    sprintf(buf,"(%s)",pname);
    return(buf);
}


void
PrintRawData(
    char *label,
    void *pfirst,
    void *plast,
    Bool octal)			/* hex or octal? */
{
    int lcount = 0;
    int count = (unsigned)plast - (unsigned)pfirst + 1;
    u_char *pch = pfirst;

    if (count <= 0)
	return;

    printf("========================================\n");
    printf("%s (%d bytes):\n", label, count);

    while (pch <= (u_char *) plast) {
	if ((*pch == '\r') && (*(pch+1) == '\n')) {
	    printf("\n");
	    ++pch;
	    lcount = 0;
	} else if (isprint(*pch)) {
	    putchar(*pch);
	    lcount+=1;
	} else {
	    if (octal) {
		printf("\\%03o", *pch);
		lcount+=4;
	    } else {
		printf("0x%02x", *pch);
		lcount+=4;
	    }
	}
	if (lcount > 70) {
	    printf("\\\n");
	    lcount = 0;
	}
	++pch;
    }
    if (lcount != 0)
	printf("\\\n");
    printf("========================================\n");
}


void
PrintRawDataHex(
    char *label,
    void *pfirst,
    void *plast)
{
    PrintRawData(label,pfirst,plast,FALSE);
}


static void
printipv6(
    struct ipv6 *pipv6,
    void *plast)
{
    int ver = (ntohl(pipv6->ip6_ver_tc_flabel) & 0xF0000000) >> 28;
    int tc  = (ntohl(pipv6->ip6_ver_tc_flabel) & 0x0F000000) >> 24;
    struct ipv6_ext *pheader;
    u_char nextheader;

    printf("\tIP  Vers: %d\n", ver);
    printf("\tIP  Srce: %s\n", ipv6addr2str(pipv6->ip6_saddr));
    printf("\tIP  Dest: %s\n", ipv6addr2str(pipv6->ip6_daddr));
    printf("\t   Class: %d\n", tc);
    printf("\t    Flow: %d\n", (ntohl(pipv6->ip6_ver_tc_flabel) & 0x00FFFFFF));
    printf("\t    PLEN: %d\n", ntohs(pipv6->ip6_lngth));
    printf("\t    NXTH: %u (%s)\n",
	   pipv6->ip6_nheader,
	   ipv6_header_name(pipv6->ip6_nheader));
    printf("\t    HLIM: %u\n", pipv6->ip6_hlimit);

    /* walk the extension headers */
    nextheader = pipv6->ip6_nheader;
    pheader = (struct ipv6_ext *)(pipv6+1);

    while (pheader) {
	u_char old_nextheader = nextheader;
	pheader = ipv6_nextheader(pheader,&nextheader);

	/* if there isn't a "next", then this isn't an extension header */
	if (pheader) {
	    printf("\tIPv6 Extension Header Type %d (%s)\n",
		   old_nextheader,
		   ipv6_header_name(old_nextheader));
	    /* FIXME - want to give details, but I need some examples first! */
	    /* (hint to users!!!...) */
	}
    }
}


/*
 * ipv6addr2str: return the string rep. of an ipv6 address
 */
static char *
ipv6addr2str(
    struct in6_addr addr)
{
    static char adr[INET6_ADDRSTRLEN];
    my_inet_ntop(AF_INET6, (char *)&addr, (char *)adr, INET6_ADDRSTRLEN);
    sprintf(adr,"%s", adr);
    return(adr);
}


/* Shawn's version... */
/* Lots of machines HAVE this, but they give slightly different formats */
/* and it messes up my cross-platform testing.  I'll just do it the */
/* "one true" way!  :-)  */
char *
ether_ntoa (struct ether_addr *e)
{
    unsigned char *pe;
    static char buf[30];

    pe = (unsigned char *) e;
    sprintf(buf,"%02x:%02x:%02x:%02x:%02x:%02x",
	    pe[0], pe[1], pe[2], pe[3], pe[4], pe[5]);
    return(buf);
}
