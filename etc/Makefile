PKGNAME = mock-urpm
FILES = `ls -1 ./mock-urpm`
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
	for d in $(SUBDIRS); do make DESTDIR=`cd $(DESTDIR); pwd` -C $$d clean; [ $$? = 0 ] || exit 1; done

install:
	echo $(DESTDIR)
	mkdir -p $(DESTDIR)/usr/share/bash-completion
	mkdir -p $(DESTDIR)/etc/bash_completion.d
	install -m 644 bash_completion/$(PKGNAME).bash $(DESTDIR)/usr/share/bash-completion/$(PKGNAME);

	#installing PAM and consolehelper
	mkdir -p  $(DESTDIR)/etc/pam.d
	install -m 644 pam/$(PKGNAME) $(DESTDIR)/etc/pam.d/$(PKGNAME);
	mkdir -p $(DESTDIR)/etc/security/console.apps
	install -m 644 consolehelper/$(PKGNAME) $(DESTDIR)/etc/security/console.apps/$(PKGNAME);

	mkdir -p $(DESTDIR)/etc/$(PKGNAME)
	for f in $(FILES); do \
		install -m 644 ./$(PKGNAME)/$$f $(DESTDIR)/etc/$(PKGNAME)/$$f; \
	done