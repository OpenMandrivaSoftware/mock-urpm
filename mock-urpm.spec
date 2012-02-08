# next four lines substituted by autoconf
%define version 1.1.12
%define release 1
%define name mock-urpm
%define modname mock_urpm

Summary: Builds packages inside chroots
Name: %{name}
Version: %{version}
Release: %{release}
License: GPLv2+
Group: System/Configuration/Packaging
Source: https://fedorahosted.org/mock/attachment/wiki/MockTarballs/%{name}-%{version}.tar.gz
URL: http://fedoraproject.org/wiki/Projects/Mock

BuildArch: noarch
Requires: python >= 2.6
Requires: tar
Requires: pigz
Requires: python-ctypes
Requires: python-decoratortools
Requires(pre): shadow-utils
Requires(post): coreutils
BuildRequires: python-devel

%description
Mock takes an SRPM and builds it in a chroot

%prep
%setup -q -n %{name}

%install
make install DESTDIR=$RPM_BUILD_ROOT

#%clean
#rm -rf $RPM_BUILD_ROOT

%pre
if [ $1 -eq 1 ]; then
    groupadd -r -f %{name} >/dev/null 2>&1 || :
    usermod -a -G %{name} `env|grep SUDO_USER | cut -f2 -d=` >/dev/null 2>&1 || :
fi

%post
# fix cache permissions from old installs
chmod 2775 /var/cache/%{name}
ln -s %{_datadir}/bash-completion/%{name} %{_sysconfdir}/bash_completion.d/%{name}

%postun
rm -f %{_sysconfdir}/bash_completion.d/%{name}

%files
%defattr(-,root,root,-)

# executables
%{_sbindir}/%{name}

# python stuff
%dir %{python_sitelib}/%{modname}
%{python_sitelib}/%{modname}/*.py
%{python_sitelib}/%{modname}/*.pyc

#bash_completion files
#%{_sysconfdir}/bash_completion.d/%{name}
%{_datadir}/bash-completion/%{name} 

# config files
%config(noreplace) %{_sysconfdir}/%{name}/logging.ini
%config(noreplace) %{_sysconfdir}/%{name}/*.cfg

#plugins
%dir %{python_sitelib}/%{modname}/plugins
%{python_sitelib}/%{modname}/plugins/*.py
%{python_sitelib}/%{modname}/plugins/*.pyc

# docs
%{_mandir}/man1/%{name}.1*

# build dir
%attr(02775, root, %{name}) %dir /var/lib/%{name}

# cache dir
%attr(02775, root, %{name}) %dir /var/cache/%{name}


%changelog
* Mon Feb 06 2012 Anton Kirilenko <anton.kirilenko@rosalab.ru> 1.1.12-1
+ Revision: 771319
- Initial commit
- Created package structure for mock-urpm.

