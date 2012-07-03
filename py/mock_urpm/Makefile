FILES = `ls -1|grep .py$$`
PLUGINS_FILES = `ls -1 ./plugins|grep .py$$`
PYTHON=python
PACKAGE=mock-urpm
PYVER := $(shell $(PYTHON) -c 'import sys; print "%.3s" %(sys.version)')
PYSYSDIR := $(shell $(PYTHON) -c 'import sys; print sys.prefix')
PYLIBDIR = $(PYSYSDIR)/lib/python$(PYVER)
PKGDIR = $(PYLIBDIR)/site-packages/mock_urpm

all:
	@echo "Nothing to do. Run 'make install' or 'make clean'"

clean:
	rm -f *.pyc *.pyo *~

install:
	mkdir -p $(DESTDIR)/$(PKGDIR)
	for f in $(FILES); do \
		install -m 644 $$f $(DESTDIR)/$(PKGDIR)/$$f; \
	done
	$(PYTHON) -c "import compileall; compileall.compile_dir('$(DESTDIR)/$(PKGDIR)', 1, '$(PKGDIR)', 1)"

	mkdir -p $(DESTDIR)/$(PKGDIR)/plugins
	for f in $(PLUGINS_FILES); do \
		install -m 644 ./plugins/$$f $(DESTDIR)/$(PKGDIR)/plugins/$$f; \
	done
	$(PYTHON) -c "import compileall; compileall.compile_dir('$(DESTDIR)/$(PKGDIR)/plugins', 1, '$(PKGDIR)/plugins', 1)"