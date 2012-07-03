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
	rm -f *~

install:
	mkdir -p $(DESTDIR)/usr/share/man/man1
	install -m 664 ./$(PKGNAME).1 $(DESTDIR)/usr/share/man/man1/$(PKGNAME).1;