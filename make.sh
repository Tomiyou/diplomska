#!/bin/bash -x

case "$1" in
clean)
	make -C xfe clean || true
	quilt pop -a -f || true
	rm -rf linux || true
	rm -rf linux.orig || true
	rm *.deb || true
    rm *.gz || true
    rm *.dsc || true
    ;;
linux)
    quilt push -a
	make -C linux clean
	make -C linux olddefconfig
    make -C linux -j 4 deb-pkg >build.log 2>&1
    ;;
xfe)
    make -C xfe
esac
