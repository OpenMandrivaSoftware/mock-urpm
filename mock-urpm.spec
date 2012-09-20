%define modname mock_urpm

Summary: Builds packages inside chroots
Name: mock-urpm
Version: 1.1.12
Release: 12
License: GPLv2+
Group: Development/Other
Source: %{name}-%{version}.tar.gz
URL: http://wiki.rosalab.ru/en/index.php/Mock-urpm

BuildArch: noarch
Requires: tar
Requires: pigz
Requires: python-ctypes
Requires: python-decoratortools
Requires: usermode-consoleonly
Requires: shadow-utils
Requires: coreutils
Requires: python-rpm
Requires: rpm-build
BuildRequires: python-devel
BuildRequires: shadow-utils
BuildRoot:  %{name}

%description
Mock-urpm takes an SRPM and builds it in a chroot

%prep
%setup -q -n %{name}

%install
make install DESTDIR=%{buildroot}
mkdir -p %{buildroot}/%{_bindir}
ln -s %{_bindir}/consolehelper %{buildroot}/%{_bindir}/%{name}
ln -s %{_datadir}/bash-completion/%{name} %{buildroot}/%{_sysconfdir}/bash_completion.d/%{name}

%pre
if [ $1 -eq 1 ]; then #first install
    groupadd -r -f %{name} >/dev/null 2>&1 || :
    if [ ! -z `env|grep SUDO_USER` ]; then
	usermod -a -G %{name} `env|grep SUDO_USER | cut -f2 -d=` >/dev/null 2>&1 || :
    fi
fi

%postun
if [ $1 -eq 0 ]; then # complete removing
  rm -f %{_sysconfdir}/%{name}/default.cfg
  groupdel %{name} >/dev/null 2>&1 || :
fi

%files
#%defattr(-,root,root,-)

# executables
%{_sbindir}/%{name}
%{_bindir}/%{name}

#consolehelper and PAM
%{_sysconfdir}/pam.d/%{name}
%{_sysconfdir}/security/console.apps/%{name}


# python stuff
%dir %{python_sitelib}/%{modname}
%{python_sitelib}/%{modname}/*.py
%{python_sitelib}/%{modname}/*.pyc

#bash_completion files
%{_datadir}/bash-completion/%{name} 
%{_sysconfdir}/bash_completion.d/%{name}

# config files
%config %{_sysconfdir}/%{name}/logging.ini
%config %{_sysconfdir}/%{name}/*.cfg

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
