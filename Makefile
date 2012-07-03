SUBDIRS = etc py doc
PKGNAME = mock-urpm

PYTHON=python
PYFILES = $(wildcard *.py)
PYVER := $(shell $(PYTHON) -c 'import sys; print "%.3s" %(sys.version)')
PYSYSDIR := $(shell $(PYTHON) -c 'import sys; print sys.prefix')
PYLIBDIR = $(PYSYSDIR)/lib/python$(PYVER)
PKGDIR = $(PYLIBDIR)/site-packages

all:
	@echo "Nothing to do. Run 'make install' or 'make clean'"

clean:
	rm -f *.pyc *.pyo *~
	rm -f *.tar.gz
	for d in $(SUBDIRS); do make DESTDIR=`cd $(DESTDIR); pwd` -C $$d clean; [ $$? = 0 ] || exit 1; done

install:
	mkdir -p $(DESTDIR)/var/lib/$(PKGNAME)
	mkdir -p $(DESTDIR)/var/cache/$(PKGNAME)
	for d in $(SUBDIRS); do make DESTDIR=`cd $(DESTDIR); pwd` -C $$d install DESTDIR=$(DESTDIR); [ $$? = 0 ] || exit 1; done