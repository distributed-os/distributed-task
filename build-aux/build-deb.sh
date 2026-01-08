#!/usr/bin/env bash

cd $(dirname $0)

source common.sh

SELF_DIR=$(pwd)
ROOT_DIR=$(dirname $SELF_DIR)

BUILD_ARCHIVE="dtts"

NR_CPUS=$(nproc 2>/dev/null)

VERSION_HEADER_FILE="${ROOT_DIR}/build-aux/libdtt.pc"
CUR_VERSION=$(get_version ${VERSION_HEADER_FILE})

CPU_ARCH="all"
TEST_BIN="/usr/bin/ls"
is_amd64=$(file ${TEST_BIN} 2>/dev/null | grep -i -E "x86-64|x86_64|amd64")
is_arm64=$(file ${TEST_BIN} 2>/dev/null | grep -i -E "aarch64|arm64")
if [ -n "$is_amd64" ]; then
    CPU_ARCH="amd64"
elif [ -n "$is_arm64" ]; then
    CPU_ARCH="arm64"
else
    pr_err "unknown cpu architecture"
    exit 1
fi

[ -e ${ROOT_DIR}/debbuild ] && rm -rf ${ROOT_DIR}/debbuild
mkdir -p ${ROOT_DIR}/debbuild/DEBIAN

cat > ${ROOT_DIR}/debbuild/DEBIAN/control << EOF
Package: ${BUILD_ARCHIVE}
Version: ${CUR_VERSION}
Section: utils
Installed-Size: 0
Priority: optional
Maintainer: DTT Team <dtt-team@dtt-project.org>
Architecture: ${CPU_ARCH}
Description: Distributed Task System.
EOF

cat > ${ROOT_DIR}/debbuild/DEBIAN/postinst << EOF
#!/bin/bash

if [ -f /usr/lib/systemd/system/dtts.service ]; then
    systemctl daemon-reload
    systemctl restart dtts.service
    systemctl enable dtts.service
fi
exit 0
EOF
chmod 755 ${ROOT_DIR}/debbuild/DEBIAN/postinst

cat > ${ROOT_DIR}/debbuild/DEBIAN/postrm << EOF
#!/bin/bash
case "\$1" in
    remove)
        systemctl stop dtts.service >/dev/null 2>&1 || true
        systemctl disable dtts.service >/dev/null 2>&1 || true
        systemctl daemon-reload
        ;;

    purge)
        systemctl stop dtts.service >/dev/null 2>&1 || true
        systemctl disable dtts.service >/dev/null 2>&1 || true
        systemctl daemon-reload
        if [ -e /var/log/dtts.log ]; then
            rm -f /var/log/dtts.log
        fi
        if [ -d /etc/dtts ]; then
            rm -rf /etc/dtts
        fi
        ;;

    *)
        ;;
esac

exit 0
EOF
chmod 755 ${ROOT_DIR}/debbuild/DEBIAN/postrm

#
# dpkg-deb -c xxx.deb
# dpkg-deb -I xxx.deb
#
pushd ${ROOT_DIR}
    mkdir -p ${ROOT_DIR}/debbuild/usr/bin
    cp -f dtts ${ROOT_DIR}/debbuild/usr/bin/
    cp -f dtt-cli/dtt ${ROOT_DIR}/debbuild/usr/bin/

    mkdir -p ${ROOT_DIR}/debbuild/usr/lib64
    cp -f dtt/lib/*.a ${ROOT_DIR}/debbuild/usr/lib64/
    cp -f dtt/lib/*.so ${ROOT_DIR}/debbuild/usr/lib64/

    mkdir -p ${ROOT_DIR}/debbuild/usr/lib64/pkgconfig
    cp -f build-aux/libdtt.pc ${ROOT_DIR}/debbuild/usr/lib64/pkgconfig/

    mkdir -p ${ROOT_DIR}/debbuild/usr/include
    cp -f dtt/include/dtt.h ${ROOT_DIR}/debbuild/usr/include/

    mkdir -p ${ROOT_DIR}/debbuild/usr/share/libdtt/examples
    cp -f examples/*.c ${ROOT_DIR}/debbuild/usr/share/libdtt/examples/
    cp -f examples/Makefile ${ROOT_DIR}/debbuild/usr/share/libdtt/examples/

    mkdir -p ${ROOT_DIR}/debbuild/usr/lib/systemd/system/
    cp -f ${ROOT_DIR}/build-aux/dtts.service ${ROOT_DIR}/debbuild/usr/lib/systemd/system/

    INSTALLED_SIZE=$(du -sk --exclude=DEBIAN debbuild | awk '{print $1}')
    if grep -q "Installed-Size" debbuild/DEBIAN/control; then
        sed -i "s/Installed-Size: .*/Installed-Size: $INSTALLED_SIZE/" debbuild/DEBIAN/control
    fi

    dpkg-deb --build debbuild ${BUILD_ARCHIVE}_${CUR_VERSION}_${CPU_ARCH}.deb
popd

exit 0
