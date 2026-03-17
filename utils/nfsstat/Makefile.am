## Process this file with automake to produce Makefile.in

man8_MANS	= nfsstat.man
EXTRA_DIST	= $(man8_MANS)

sbin_PROGRAMS	= nfsstat
nfsstat_SOURCES = nfsstat.c
nfsstat_CFLAGS = $(LIBNL3_CFLAGS) $(LIBNLGENL3_CFLAGS)
nfsstat_LDADD = ../../support/export/libexport.a \
	      	../../support/nfs/libnfs.la \
		../../support/misc/libmisc.a \
		$(LIBNL3_LIBS) $(LIBNLGENL3_LIBS)

MAINTAINERCLEANFILES = Makefile.in
