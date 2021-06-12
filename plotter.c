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
    "@(#)$Header: /home/sdo/src/tcptrace/RCS/plotter.c,v 3.9 1997/03/04 18:11:21 sdo Exp $";

#include "tcptrace.h"


/* locally global parameters */
static int max_plotters;
static MFILE **fplot;
static tcb **p2plast;
static PLOTTER plotter_ix = NO_PLOTTER;
static char *temp_color = NULL;


/* local routine declarations */
static char *xp_timestamp(struct timeval time);
static char *TSGPlotName(tcb *plast, PLOTTER, char *suffix);
static void DoPlot(PLOTTER pl, char *fmt, ...);





/*
 * Return a string suitable for use as a timestamp in the xplot output.
 * (Currently rounds to the nearest 1/10 millisecond)
 */
static char *
xp_timestamp(
    struct timeval time)
{
    static char bufs[4][20];	/* several of them for multiple calls in one printf */
    static int bufix = 0;
    unsigned secs = time.tv_sec;
    unsigned usecs = time.tv_usec;
    unsigned decimal = usecs / 100;  /* just truncate, faster */
    char *pbuf;

    bufix = (bufix+1)%4;
    pbuf = bufs[bufix];

    sprintf(pbuf,"%u.%04u",secs,decimal);
    return(pbuf);
}



void
plot_init(void)
{
    max_plotters = 256;  /* just a default, make more on the fly */

    fplot = (MFILE **) MallocZ(max_plotters * sizeof(MFILE *));
    p2plast = (tcb **) MallocZ(max_plotters * sizeof(tcb *));
}


static void
plotter_makemore(void)
{
    int new_max_plotters = max_plotters * 4;

    if (debug)
	fprintf(stderr,"plotter: making more space for %d total plotters\n",
		new_max_plotters);

    /* reallocate the memory to make more space */
    fplot = ReallocZ(fplot,
		     max_plotters * sizeof(MFILE *),
		     new_max_plotters * sizeof(MFILE *));
    p2plast = ReallocZ(p2plast,
		       max_plotters * sizeof(tcb *),
		       new_max_plotters * sizeof(tcb *));

    max_plotters = new_max_plotters;
}




/* max number of letters in endpoint name */
/* (8 allows 26**8 different endpoints (209,000,000,000)
    probably plenty for now!!!!!) */
#define MAX_HOSTLETTER_LEN 8
char *
HostLetter(
     unsigned ix)
{
    static char name[MAX_HOSTLETTER_LEN+1];
    static char *pname;

    /* basically, just convert to base 26 */
    pname = &name[sizeof(name)-1];
    *pname-- = '\00';
    while (pname >= name) {
	unsigned digit = ix % 26;
	*pname-- = 'a'+digit;
	ix = ix / 26;
	if (ix == 0)
	    return(pname+1);
    }

    fprintf(stderr,"Fatal, too many hosts to name (max length %d)\n",
	    MAX_HOSTLETTER_LEN);
    exit(-1);
    return(NULL);  /* NOTREACHED */
}



static char *
TSGPlotName(
    tcb *plast,
    PLOTTER pl,
    char *suffix)
{
    static char filename[25];

    sprintf(filename,"%s2%s%s",
	    plast->host_letter, plast->ptwin->host_letter, suffix);

    return(filename);
}



static void
DoPlot(
     PLOTTER	pl,
     char	*fmt,
     ...)
{
    va_list	ap;
    MFILE *f = NULL;

    va_start(ap,fmt);

/*     if (!graph_tsg) */
/* 	return; */

    if (pl == NO_PLOTTER) {
	va_end(ap);
	return;
    }

    if (pl > plotter_ix) {
	fprintf(stderr,"Illegal plotter: %d\n", pl);
	exit(-1);
    }

    if ((f = fplot[pl]) == NULL) {
	va_end(ap);
	return;
    }

    Mvfprintf(f,fmt,ap);
    if (temp_color) {
	Mfprintf(f," %s",temp_color);
	temp_color = NULL;
    }
    Mfprintf (f,"\n");

    va_end(ap);

    return;
}


PLOTTER
new_plotter(
    tcb *plast,
    char *title,
    char *xlabel,
    char *ylabel,
    char *suffix)
{
    PLOTTER pl;
    MFILE *f;
    char *filename;

    ++plotter_ix;
    if (plotter_ix >= max_plotters) {
	plotter_makemore();
    }

    pl = plotter_ix;

    filename = TSGPlotName(plast,pl,suffix);

    if (debug)
	fprintf(stderr,"Plotter %d file is '%s'\n", pl, filename);

    if ((f = Mfopen(filename,"w")) == NULL) {
	perror(filename);
	return(NO_PLOTTER);
    }

    Mfprintf(f,"timeval unsigned\n");
    Mfprintf(f,"title\n%s\n", title);
    Mfprintf(f,"xlabel\n%s\n", xlabel);
    Mfprintf(f,"ylabel\n%s\n", ylabel);

    fplot[pl] = f;
    p2plast[pl] = plast;

    return(pl);
}


void
plotter_done(void)
{
    PLOTTER pl;
    MFILE *f;
    char *fname;

    for (pl = 0; pl < plotter_ix; ++pl) {
	if ((f = fplot[pl]) == NULL)
	    continue;
	
	if (!ignore_non_comp || ConnComplete(p2plast[pl]->ptp)) {
	    Mfprintf(f,"go\n");
	    Mfclose(f);
	} else {
	    fname = p2plast[pl]->tsg_plotfile;
	    if (debug)
		fprintf(stderr,"Removing incomplete plot file '%s'\n",
			fname);
	    Mfclose(f);
	    if (unlink(fname) != 0)
		perror(fname);
	}
    }
}



void
plotter_temp_color(
    PLOTTER pl,
    char *color)
{
    if (colorplot)
	temp_color = color;
}


void
plotter_perm_color(
    PLOTTER pl,
    char *color)
{
    if (colorplot)
	DoPlot(pl,"%s",color);
}


void
plotter_line(
    PLOTTER pl,
    struct timeval	t1,
    u_long		x1,
    struct timeval	t2,
    u_long		x2)
{
    DoPlot(pl,"line %s %u %s %u",
	   xp_timestamp(t1), x1,
	   xp_timestamp(t2), x2);
}


void
plotter_dline(
    PLOTTER pl,
    struct timeval	t1,
    u_long		x1,
    struct timeval	t2,
    u_long		x2)
{
    DoPlot(pl,"dline %s %u %s %u",
           xp_timestamp(t1), x1,
           xp_timestamp(t2), x2);
}


void
plotter_diamond(
    PLOTTER pl,
    struct timeval	t,
    u_long		x)
{
    DoPlot(pl,"diamond %s %u", xp_timestamp(t), x);
}


void
plotter_dot(
    PLOTTER pl,
    struct timeval	t,
    u_long		x)
{
    DoPlot(pl,"dot %s %u", xp_timestamp(t), x);
}


void
plotter_plus(
    PLOTTER pl,
    struct timeval	t,
    u_long		x)
{
    DoPlot(pl,"plus %s %u", xp_timestamp(t), x);
}


void
plotter_box(
    PLOTTER pl,
    struct timeval	t,
    u_long		x)
{
    DoPlot(pl,"box %s %u", xp_timestamp(t), x);
}



void
plotter_arrow(
    PLOTTER pl,
    struct timeval	t,
    u_long		x,
    char	dir)
{
    DoPlot(pl,"%carrow %s %u", dir, xp_timestamp(t), x);
}


void
plotter_uarrow(
    PLOTTER pl,
    struct timeval	t,
    u_long		x)
{
    plotter_arrow(pl,t,x,'u');
}


void
plotter_darrow(
    PLOTTER pl,
    struct timeval	t,
    u_long		x)
{
    plotter_arrow(pl,t,x,'d');
}


void
plotter_rarrow(
    PLOTTER pl,
    struct timeval	t,
    u_long		x)
{
    plotter_arrow(pl,t,x,'r');
}


void
plotter_larrow(
    PLOTTER pl,
    struct timeval	t,
    u_long		x)
{
    plotter_arrow(pl,t,x,'l');
}


void
plotter_tick(
    PLOTTER pl,
    struct timeval	t,
    u_long		x,
    char		dir)
{
    DoPlot(pl,"%ctick %s %u", dir, xp_timestamp(t), x);
}


void
plotter_dtick(
    PLOTTER pl,
    struct timeval	t,
    u_long		x)
{
    plotter_tick(pl,t,x,'d');
}


void
plotter_utick(
    PLOTTER pl,
    struct timeval	t,
    u_long		x)
{
    plotter_tick(pl,t,x,'u');
}


void
plotter_ltick(
    PLOTTER pl,
    struct timeval	t,
    u_long		x)
{
    plotter_tick(pl,t,x,'l');
}


void
plotter_rtick(
    PLOTTER pl,
    struct timeval	t,
    u_long		x)
{
    plotter_tick(pl,t,x,'r');
}


void
plotter_htick(
    PLOTTER pl,
    struct timeval	t,
    u_long		x)
{
    plotter_tick(pl,t,x,'h');
}


void
plotter_vtick(
    PLOTTER pl,
    struct timeval	t,
    u_long		x)
{
    plotter_tick(pl,t,x,'v');
}



void
plotter_text(
    PLOTTER pl,
    struct timeval	t,
    u_long		x,
    char		*where,
    char		*str)
{
    DoPlot(pl,"%stext %s %u", where, xp_timestamp(t), x);
    /* fix by Bill Fenner - Wed Feb  5, 1997, thanks */
    /* This is a little ugly.  Text commands take 2 lines. */
    /* A temporary color could have been */
    /* inserted after that line, but would NOT be inserted after */
    /* the next line, so we'll be OK.  I can't think of a better */
    /* way right now, and this works fine (famous last words) */
    DoPlot(pl,"%s", str);
}
