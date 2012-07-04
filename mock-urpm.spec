%define modname mock_urpm

Summary: Builds packages inside chroots
Name: mock-urpm
Version: 1.1.12
Release: 10
License: GPLv2+
Group: Development/Other
Source: %{name}-%{version}.tar.gz
URL: http://wiki.mandriva.com/en/Mock-urpm

BuildArch: noarch
Requires: tar
Requires: pigz
Requires: python-ctypes
Requires: python-decoratortools
Requires: usermode-consoleonly
Requires: shadow-utils
Requires: coreutils
BuildRequires: python-devel
BuildRequires: shadow-utils
BuildRoot:  %{name}-%{version}

%description
Mock takes an SRPM and builds it in a chroot

%prep
%setup -q -n %{name}-%{version}

%install
make install DESTDIR=$RPM_BUILD_ROOT

#%clean
#rm -rf $RPM_BUILD_ROOT

%pre
if [ $1 -eq 1 ]; then #first install
    groupadd -r -f %{name} >/dev/null 2>&1 || :
    if [ ! -z `env|grep SUDO_USER` ]; then
	usermod -a -G %{name} `env|grep SUDO_USER | cut -f2 -d=` >/dev/null 2>&1 || :
    fi
fi


%post
if [ $1 -eq 1 ]; then #first install
  ln -s -f %{_datadir}/bash-completion/%{name} %{_sysconfdir}/bash_completion.d/%{name}
  ln -s -f %{_bindir}/consolehelper %{_bindir}/%{name} 
fi

%postun
if [ $1 -eq 0 ]; then # complete removing
  rm -f %{_sysconfdir}/bash_completion.d/%{name}
  rm -f $cfg %{_sysconfdir}/%{name}/default.cfg
  rm -f %{_bindir}/%{name} 
  groupdel %{name} >/dev/null 2>&1 || :
fi

%files
%defattr(-,root,root,-)

# executables
%{_sbindir}/%{name}

#consolehelper and PAM
%{_sysconfdir}/pam.d/%{name}
%{_sysconfdir}/security/console.apps/%{name}

# python stuff
%dir %{python_sitelib}/%{modname}
%{python_sitelib}/%{modname}/*.py
%{python_sitelib}/%{modname}/*.pyc

#bash_completion files
#%{_sysconfdir}/bash_completion.d/%{name}
%{_datadir}/bash-completion/%{name} 

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
