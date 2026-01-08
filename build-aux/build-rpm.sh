#!/usr/bin/env bash

cd $(dirname $0)

source common.sh

SELF_DIR=$(pwd)
ROOT_DIR=$(dirname $SELF_DIR)

BUILD_ARCHIVE="dtts"

NR_CPUS=$(nproc 2>/dev/null)

VERSION_HEADER_FILE="${ROOT_DIR}/build-aux/libdtt.pc"
CUR_VERSION=$(get_version ${VERSION_HEADER_FILE})

[ -e ${ROOT_DIR}/rpmbuild ] && rm -rf ${ROOT_DIR}/rpmbuild
mkdir -p ${ROOT_DIR}/rpmbuild/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS}

cat > ${ROOT_DIR}/rpmbuild/SPECS/${BUILD_ARCHIVE}.spec << EOF
Name:           ${BUILD_ARCHIVE}
Version:        ${CUR_VERSION}
Release:        1
Summary:        Distributed Task System

License:        MIT
URL:            https://www.dtt-project.org
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  make
BuildRequires:  gcc

%description
An ultra-lightweight distributed task system written in pure C.

%prep
# %setup -q

%build

%install
mkdir -p %{buildroot}
mkdir -p %{buildroot}/usr/bin
mkdir -p %{buildroot}/usr/lib64
mkdir -p %{buildroot}/usr/lib64/pkgconfig
mkdir -p %{buildroot}/usr/include
mkdir -p %{buildroot}/usr/share/libdtt/examples
mkdir -p %{buildroot}/usr/lib/systemd/system
cp -f ${ROOT_DIR}/dtts %{buildroot}/usr/bin/
cp -f ${ROOT_DIR}/dtt-cli/dtt %{buildroot}/usr/bin/
cp -f ${ROOT_DIR}/dtt/lib/*.a %{buildroot}/usr/lib64/
cp -f ${ROOT_DIR}/dtt/lib/*.so %{buildroot}/usr/lib64/
cp -f ${ROOT_DIR}/build-aux/libdtt.pc %{buildroot}/usr/lib64/pkgconfig/
cp -f ${ROOT_DIR}/dtt/include/dtt.h %{buildroot}/usr/include/
cp -f ${ROOT_DIR}/examples/*.c %{buildroot}/usr/share/libdtt/examples/
cp -f ${ROOT_DIR}/examples/Makefile %{buildroot}/usr/share/libdtt/examples/
cp -f ${ROOT_DIR}/build-aux/dtts.service %{buildroot}/usr/lib/systemd/system/

%files
/usr/bin/dtts
/usr/bin/dtt
/usr/lib64/libdtt.so
/usr/lib64/libdtt.a
/usr/lib64/pkgconfig/libdtt.pc
/usr/include/dtt.h
/usr/share/libdtt/
/usr/lib/systemd/system/dtts.service

%post
if [ -f /usr/lib/systemd/system/dtts.service ]; then
    systemctl daemon-reload >/dev/null 2>&1 || :
    systemctl enable dtts.service >/dev/null 2>&1 || :
    systemctl restart dtts.service >/dev/null 2>&1 || :
fi

%preun
if [ \$1 -eq 0 ]; then
    systemctl stop dtts.service >/dev/null 2>&1 || :
    systemctl disable dtts.service >/dev/null 2>&1 || :
fi

%changelog
* Thu Nov 27 2025 Anonymous <anonymous@example.com> - 0.1.1
- Initial RPM release

EOF

pushd ${ROOT_DIR}
    rpmbuild --bb --define "_topdir ${dir:-$(pwd)/rpmbuild}" rpmbuild/SPECS/${BUILD_ARCHIVE}.spec
    mv rpmbuild/RPMS/$(uname -m)/*.rpm ./
popd

exit 0
