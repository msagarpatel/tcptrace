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
static char const rcsid_compress[] =
    "$Header: /home/sdo/src/tcptrace/src/RCS/compress.h,v 5.2 1999/02/25 15:01:37 sdo Exp $";

#define COMP_HDR_SIZE (8*1024)	/* number of bytes from a compressed file that */
				/* we save into a real file for header check, */
				/* the rest we read from a pipe (if long) */


/* How to identify various comp formats */
#define COMP_MAX_ARGS 20	/* maximum args that you can specify */
struct comp_formats {
    char	*comp_suffix;	/* how to recognize these files		*/
    char	*comp_descr;	/* description of the file format	*/
    char	*comp_bin;	/* name of the binary (full path preferred) */
    char	*comp_args[COMP_MAX_ARGS]; /* arguments to pass */
};

/*
 * compression format table:
 * Don't forget:!!!
 *  1) Leave the last line of NULLs alone
 *  2) arg 1 MUST be the name of the program
 *  3) last arg MUST be NULL
 *  4) only the first suffix match is used
 *  5) an arg of "%s" will be replaced with the file name,
 *     don't forget to include it!
 *  6) don't forget the "dot" in the suffix (if there is one)
 */

struct comp_formats supported_comp_formats[] = {
/*   SUFFIX    DESCRIPTION	    BINARY NAME	   ARGS TO EXECV	*/
/*   -----   --------------------   -----------   ----------------------*/
#ifdef GUNZIP
    {".gz", "Gnu gzip format",	    GUNZIP,     {"gunzip","-c","%s",NULL}},
    {".Z",  "Unix compress format", GUNZIP,     {"gunzip","-c","%s",NULL}},
#endif /* GUNZIP */

#ifdef UNCOMPRESS
    {".Z",  "Unix compress format", UNCOMPRESS, {"uncompress","-c","%s",NULL}},
#endif /* UNCOMPRESS */
};
#define NUM_COMP_FORMATS (sizeof(supported_comp_formats) / sizeof(struct comp_formats))

