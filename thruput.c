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
    "@(#)$Header: /home/sdo/src/tcptrace/src/RCS/thruput.c,v 5.2 1999/02/25 15:01:26 sdo Exp $";


#include "tcptrace.h"


void
DoThru(
    tcb *ptcb,
    int nbytes)
{
    double etime;
    double thruput;
    char *myname, *hisname;

    /* init, if not already done */
    if (ZERO_TIME(&ptcb->thru_firsttime)) {
	char title[210];

	ptcb->thru_firsttime = current_time;
	ptcb->thru_lasttime = current_time;
	ptcb->thru_pkts = 1;
	ptcb->thru_bytes = nbytes;
	

	/* bug fix from Michele Clark - UNC */
	if (&ptcb->ptp->a2b == ptcb) {
	    myname = ptcb->ptp->a_endpoint;
	    hisname = ptcb->ptp->b_endpoint;
	} else {
	    myname = ptcb->ptp->b_endpoint;
	    hisname = ptcb->ptp->a_endpoint;
	}
	/* create the plotter file */
	sprintf(title,"%s_==>_%s (throughput)",
		myname, hisname);
	ptcb->thru_plotter = new_plotter(ptcb,NULL,title,
					 "time","thruput (bytes/sec)",
					 THROUGHPUT_FILE_EXTENSION);
	if (graph_time_zero) {
	    /* set graph zero points */
	    plotter_nothing(ptcb->thru_plotter, current_time);
	}

	/* create lines for average and instantaneous values */
	ptcb->thru_avg_line =
	    new_line(ptcb->thru_plotter, "avg. tput", "blue");
	ptcb->thru_inst_line =
	    new_line(ptcb->thru_plotter, "inst. tput", "red");

	return;
    }

    /* if no data, then nothing to do */
    if (nbytes == 0)
	return;

    /* see if we should output the stats yet */
    if (ptcb->thru_pkts+1 >= thru_interval) {

	/* compute stats for this interval */
	etime = elapsed(ptcb->thru_firsttime,current_time);
	if (etime == 0.0)
	    etime = 1000;	/* ick, what if "no time" has passed?? */
	thruput = (double) ptcb->thru_bytes / ((double) etime / 1000000.0);

	/* instantaneous plot */
	extend_line(ptcb->thru_inst_line,
		     current_time, (int) thruput);

	/* compute stats for connection lifetime */
	etime = elapsed(ptcb->ptp->first_time,current_time);
	if (etime == 0.0)
	    etime = 1000;	/* ick, what if "no time" has passed?? */
	thruput = (double) ptcb->data_bytes / ((double) etime / 1000000.0);

	/* long-term average */
	extend_line(ptcb->thru_avg_line,
		     current_time, (int) thruput);

	/* reset stats for this interval */
	ptcb->thru_firsttime = current_time;
	ptcb->thru_pkts = 0;
	ptcb->thru_bytes = 0;
    }

    /* immediate value in yellow ticks */
    if (plot_tput_instant) {
	etime = elapsed(ptcb->thru_lasttime,current_time);
	if (etime == 0.0)
	    etime = 1000;	/* ick, what if "no time" has passed?? */
	thruput = (double) nbytes / ((double) etime / 1000000.0);
	plotter_temp_color(ptcb->thru_plotter,"yellow");
	plotter_dot(ptcb->thru_plotter,
		    current_time, (int) thruput);
    }

    /* add in the latest packet */
    ptcb->thru_lasttime = current_time;
    ++ptcb->thru_pkts;
    ptcb->thru_bytes += nbytes;
}
