# Generated automatically from Makefile.in by configure.
#
# Makefile for tcptrace
#


################################################################## 
#
# tcptrace supports reading compressed files with a little help...
# 1) If your system has "gunzip", then uncomment the following line to
#    support on-the-fly decompression of ".gz" and ".Z" files...
DEFINES += -DGUNZIP="\"gunzip\""
# 2) Otherwise, if your system supports standard Unix "uncompress",
#    then uncomment the following line to support on-the-fly
#    decompression of ".Z" files...
#DEFINES += -DUNCOMPRESS="\"uncompress\""
# - we'll do path search on the string you specify.  If the program
#    isn't in your path, you'll need to give the absolute path name.
# - if you want other formats, see the "compress.h" file.




################################################################## 
#
# If you want to read tcpdump output (which you probably do),
# you'll need the LBL PCAP library.  I've just listed a bunch
# of places that it might be (other than the standard
# location).  If it's somewhere else, just add it into the
# list.
# 
################################################################## 
PCAP_LDLIBS = -lpcap
PCAP_INCS    = -I/usr/local/include -I. -I../pcap
PCAP_LDFLAGS = -L/usr/local/lib -Llib -Lpcap -L../pcap



################################################################## 
# 
# Plug-in modules.
# There's no reason that I can think of to remove them, but
# here they are.  Just comment them out to omit them from
# the binary.
# 
################################################################## 
# 
# Experimental HTTP analysis module
# 
DEFINES += -DLOAD_MODULE_HTTP
# 
# Experimental overall traffic by port module
# 
DEFINES += -DLOAD_MODULE_TRAFFIC
# 
# Experimental round trip time graphs
# 
DEFINES += -DLOAD_MODULE_RTTGRAPH
# 
# Experimental tcplib-data generating module
# 
DEFINES += -DLOAD_MODULE_TCPLIB
# 
# Experimental module for a friend
# 
DEFINES += -DLOAD_MODULE_COLLIE



################################################################## 
# 
# File formats that we understand.
# The only reason that I can see to remove one is if you don't
# have the PCAP library, in which case you can comment out
# GROK_TCPDUMP and still compile, but then you can't read the
# output from tcpdump.
# 
################################################################## 
# define GROK_SNOOP if you want tcptrace to understand the output
# format of Sun's "snoop" packet sniffer.
DEFINES += -DGROK_SNOOP
# define GROK_TCPDUMP if you want tcptrace to understand the output
# format format of the LBL tcpdump program (see the file README.tcpdump
# for other options)
DEFINES += -DGROK_TCPDUMP
# define GROK_NETM if you want tcptrace to understand the output
# format of HP's "netm" monitoring system's packet sniffer.
DEFINES += -DGROK_NETM
# define GROK_ETHERPEEK if you want tcptrace to understand the output
# format of the Macintosh program Etherpeek
DEFINES += -DGROK_ETHERPEEK




################################################################## 
################################################################## 
################################################################## 
# 
# You shouldn't need to change anything below this point
# 
################################################################## 
################################################################## 
################################################################## 

CC = gcc
CCOPT = -O2 -Wall -Werror -g
INCLS = -I.  ${PCAP_INCS}

# Standard CFLAGS
# Probably want full optimization
# FreeBSD needs	-Ae
# HP needs	-Ae
CFLAGS = $(CCOPT) $(DEFINES)  -DHAVE_LIBM=1 -DSIZEOF_UNSIGNED_LONG_LONG_INT=8 -DHAVE_LIBNSL=1 -DHAVE_LIBSOCKET=1 -DHAVE_ETHER_NTOA=1 -DHAVE_MKSTEMP=1   $(INCLS)

# Standard LIBS
LDLIBS = -lsocket -lnsl -lm  ${PCAP_LDLIBS}
# for solaris, you probably want:
#	LDLIBS = -lpcap -lnsl -lsocket -lm
# for HP, I'm told that you need:
#	LDLIBS = -lpcap -lstr -lm
# everybody else (that I know of) just needs:
#	LDLIBS = -lpcap -lm
# 
LDFLAGS += ${PCAP_LDFLAGS}



# for profiling (under Solaris, at least)
#CFLAGS	+= -pg
#LDFLAGS += /usr/lib/libdl.so.1


# Source Files
CFILES=compress.c etherpeek.c gcache.c mfiles.c missing.c names.c \
	netm.c output.c plotter.c print.c rexmit.c snoop.c	\
	tcpdump.c tcptrace.c thruput.c trace.c ipv6.c	\
	filt_scanner.c filt_parser.c filter.c udp.c \
	version.c
MODULES=mod_http.c mod_traffic.c mod_rttgraph.c mod_tcplib.c mod_collie.c
OFILES= ${CFILES:.c=.o} ${MODULES:.c=.o}

all: tcptrace versnum

tcptrace: ${OFILES}
	${CC} ${LDFLAGS} ${CFLAGS} ${OFILES} -o tcptrace ${LDLIBS}

#
# special rule for version.c
# needs to be recompiled EVERY time
#
# If you have problems getting "whoami", "hostname", or "date" to run on
# your machine, just hack in a quick string below in place of the command.
version.o: ${CFILES} Makefile
	${CC} ${CFLAGS} -o version.o -c version.c \
	-DBUILT_USER="\"`whoami`\"" -DBUILT_HOST="\"`hostname`\"" -DBUILT_DATE="\"`date`\""

#
# special rules for scanner/parser
#
# Note that I'm using the GNU bison/flex to get around the problems
# caused by the fact that that pcap library ALSO uses YACC, which can
# cause naming conflicts.  The Gnu versions let you get around that
# easily.
#
filt_parser.c: filt_parser.y filter.h
	bison -vd -p filtyy filt_parser.y -o filt_parser.c
	cp filt_parser.c flex_bison
	cp filt_parser.h flex_bison
filt_scanner.c: filt_scanner.l filter.h filt_parser.h
	flex -t -Pfiltyy filt_scanner.l > filt_scanner.c
	cp filt_scanner.c flex_bison
# filt_parser.h created as a side effect of running yacc...
filt_parser.h: filt_parser.c

# version numbering program
versnum: versnum.c version.h
	${CC} ${LDFLAGS} ${CFLAGS} versnum.c -o versnum ${LDLIBS}

#
# obvious dependencies
#
${OFILES}: tcptrace.h


#
# just for RCS
ci:
	ci -u -q -t-initial -mlatest *.c *.h \
		Makefile.in configure.in config.guess config.sub aclocal.m4 \
		README* INSTALL* CHANGES WWW COPYRIGHT

#
# for cleaning up
clean:
	rm -f *.o tcptrace versnum core *.xpl *.dat .devel \
		config.cache config.log config.status bin.* \
		filt_scanner.c filt_parser.c y.tab.h y.output PF \
		filt_parser.output filt_parser.h
	cd input; ${MAKE} clean

noplots:
	rm -f *.xpl *.dat

#
# for making distribution
tarfile: versnum
	@ VERS=`./versnum`; DIR=tcptrace_$${VERS}; \
	GZTAR=$$HOME/tcptrace.$${VERS}.tar.gz; \
	cd ..; \
	test -h $${DIR} || ln -s src $${DIR}; \
	/usr/sbin/tar -FFcvhf - $${DIR} | gzip > $${GZTAR}; \
	echo ; echo "Tarfile is in $${GZTAR}"
#
# similar, but include RCS directory and etc
bigtarfile:
	cd ..; /usr/sbin/tar -cfv $$HOME/tcptrace.tar tcptrace


#
# static file dependencies
#
filter.o: filter.h filter_vars.h
etherpeek.o: tcptrace.h 
gcache.o: tcptrace.h  gcache.h
mfiles.o: tcptrace.h 
mod_http.o: tcptrace.h  mod_http.h
names.o: tcptrace.h  gcache.h
netm.o: tcptrace.h 
output.o: tcptrace.h  gcache.h
plotter.o: tcptrace.h 
print.o: tcptrace.h 
rexmit.o: tcptrace.h 
rtt.o: tcptrace.h 
snoop.o: tcptrace.h 
tcpdump.o: tcptrace.h tcpdump.h 
tcptrace.o: tcptrace.h  file_formats.h modules.h mod_http.h version.h
thruput.o: tcptrace.h 
trace.o: tcptrace.h  gcache.h
udp.o: tcptrace.h  gcache.h
compress.o: tcptrace.h  compress.h
mod_http.o: tcptrace.h 
mod_traffic.o: tcptrace.h  mod_traffic.h
mod_tcplib.o: tcptrace.h  mod_tcplib.h
mod_rttgraph.o: tcptrace.h  mod_rttgraph.h
ipv6.o: tcptrace.h ipv6.h

#
# make development version
develop devel:
	touch .devel

configure: configure.in
	autoconf


#
# generate dependencies
depend:
	makedepend ${INCS} -w 10 *.c
