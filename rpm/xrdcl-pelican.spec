
Name: xrdcl-pelican
Version: 0.9.0
Release: 1%{?dist}
Summary: A Pelican-specific backend for the XRootD client

Group: System Environment/Daemons
License: BSD
URL: https://github.com/pelicanplatform/xrdcl-pelican
# Generated from:
# git archive v%{version} --prefix=xrdcl-pelican-%{version}/ | gzip -7 > ~/rpmbuild/SOURCES/xrdcl-pelican-%{version}.tar.gz
Source0: %{name}-%{version}.tar.gz

%define xrootd_current_major 5
%define xrootd_current_minor 6
%define xrootd_next_major 6

%if 0%{?rhel} > 8
%global __cmake_in_source_build 1
%endif

BuildRoot: %(mktemp -ud %{_tmppath}/%{name}-%{version}-%{release}-XXXXXX)
BuildRequires: xrootd-devel >= 1:%{xrootd_current_major}
BuildRequires: xrootd-devel <  1:%{xrootd_next_major}
BuildRequires: xrootd-client-devel >= 1:%{xrootd_current_major}
BuildRequires: xrootd-client-devel <  1:%{xrootd_next_major}
BuildRequires: cmake3
BuildRequires: gcc-c++
BuildRequires: curl-devel
%{?systemd_requires}
# For %{_unitdir} macro
BuildRequires: systemd

Requires: xrootd-client >= 1:%{xrootd_current_major}.%{xrootd_current_minor}
Requires: xrootd-client <  1:%{xrootd_next_major}.0.0-1

%description
%{summary}

%prep
%setup -q

%build
%cmake3 -DCMAKE_BUILD_TYPE=RelWithDebInfo .
make VERBOSE=1 %{?_smp_mflags}

%install
rm -rf $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root,-)
%{_libdir}/libXrdClPelican-*.so
%{_sysconfdir}/xrootd/client.plugins.d/pelican-plugin.conf

%changelog
* Sun Dec 10 2023 Brian Bockelman <brian.bockelman@cern.ch> - 0.9.0-1
- Initial packaging of the Pelican client

