## Process this file with automake to produce Makefile.in
PYTHON_FILES = nfsd-iomode-advisor.py

man8_MANS       = nfsd-iomode-advisor.man

EXTRA_DIST      = $(man8_MANS) $(PYTHON_FILES)

all-local: $(PYTHON_FILES)

install-data-hook:
	$(MKDIR_P) $(DESTDIR)$(sbindir)
	$(INSTALL) -m 755 nfsd-iomode-advisor.py $(DESTDIR)$(sbindir)/nfsd-iomode-advisor

MAINTAINERCLEANFILES=Makefile.in
