#
# Makefile for tcptrace
#

#
# According to Jeff Semke, this define allows the program to compile
# and run under NetBSD on a pentium box.
#
#DEFINES = -DI386_NBSD1

#
# According to Rich Jones at HP, there is no ether_ntoa under HPUX.
# I added one in the file missing.c
# If _YOU_ need it, just define NEED_ETHER_NTOA
#
#DEFINES = -DNEED_ETHER_NTOA
#


#   
# User-configurable constants
#
CC	= gcc
#
# If you're using the pcap library, you'll need to add it's include
# and library location, otherwise the default should be fine
# 
INCS	= -I/usr/local/include
LDFLAGS = -L/usr/local/lib

#
# For HP:  (Rick Jones)
# CFLAGS	= -Ae -Wall ${INCS}
#
# For Solaris:
#   Warning, without -fno-builtin, a bug in gcc 2.7.2 forces an
#   alignment error on my Sparc when it re-writes memcpy()...
#
#CFLAGS	= -g -O3 -fno-builtin -Wall ${INCS} ${DEFINES}
#
CFLAGS	= -g -O3 -fno-builtin -Wall ${INCS} ${DEFINES}


#
# All the different libraries, differ from machine to machine
#
# Math library required (on most machines, at least)
#
# For Solaris
# LDLIBS = -lpcap -lnsl -lsocket -lm
#
# For HP
# LDLIBS = -lpcap -lstr -lm
#
# for general Unix boxes (I hope)
# LDLIBS = -lpcap -lm
#
LDLIBS = -lpcap -lnsl -lsocket -lm



CFILES= etherpeek.c gcache.c tcptrace.c mfiles.c names.c netm.c output.c \
	plotter.c print.c snoop.c tcpdump.c thruput.c trace.c rexmit.c \
	missing.c
OFILES= ${CFILES:.c=.o}


tcptrace: ${OFILES}
	${CC} ${LDFLAGS} ${CFLAGS} ${OFILES} -o tcptrace ${LDLIBS}


#
# obvious dependencies
#
${OFILES}: tcptrace.h config.h


#
# just for RCS
ci:
	ci -u -q -t-initial -mlatest Makefile *.h *.c

#
# for cleaning up
clean:
	rm -f *.o tcptrace core *.xpl *.dat
noplots:
	rm -f *.xpl *.dat

#
# for making distribution
tarfile:
	cd ..; /usr/sbin/tar -FFcfv $$HOME/tcptrace.tar tcptrace


#
# generate dependencies
depend:
	makedepend ${INCS} -w 10 *.c
# DO NOT DELETE THIS LINE -- make depend depends on it.

etherpeek.o: tcptrace.h
etherpeek.o: config.h
gcache.o: tcptrace.h
gcache.o: config.h
gcache.o: gcache.h
mfiles.o: tcptrace.h
mfiles.o: config.h
names.o: tcptrace.h
names.o: config.h
names.o: gcache.h
netm.o: tcptrace.h
netm.o: config.h
output.o: tcptrace.h
output.o: config.h
output.o: gcache.h
plotter.o: tcptrace.h
plotter.o: config.h
print.o: tcptrace.h
print.o: config.h
rexmit.o: tcptrace.h
rexmit.o: config.h
rtt.o: tcptrace.h
rtt.o: config.h
snoop.o: tcptrace.h
snoop.o: config.h
tcpdump.o: tcptrace.h
tcpdump.o: config.h
tcptrace.o: tcptrace.h
tcptrace.o: config.h
tcptrace.o: file_formats.h
tcptrace.o: version.h
thruput.o: tcptrace.h
thruput.o: config.h
trace.o: tcptrace.h
trace.o: config.h
trace.o: gcache.h
