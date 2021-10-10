#!/bin/bash -x

linux_ver="5.14.10"
linux_conf=linux-config-5.10
debian_pkg=${linux_conf}_5.10.70-1_amd64.deb

if [[ ! -d linux ]]; then
    echo "Cloning linux ${linux_ver}"
    git clone --depth 1 --branch v${linux_ver} git://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git
fi

if [[ ! -f ${debian_pkg} ]]; then
    wget http://ftp.debian.org/debian/pool/main/l/linux/${debian_pkg}
    dpkg --fsys-tarfile ${debian_pkg} | tar xOf - ./usr/src/${linux_conf}/config.amd64_none_amd64.xz | xzcat > linux/.config
fi
