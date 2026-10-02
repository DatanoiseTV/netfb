#!/bin/bash
# Builds the test initramfs inside the kernel-build container.
#   in:  /src (this repo, read-only), /vol/linux-<ver> (built kernel tree)
#   out: /out/Image, /out/initramfs.cpio.gz
set -euo pipefail
V=${1:?kernel version}
K=/vol/linux-$V

# Built-in kernel: its exported symbols are all the module needs to resolve against.
[ -f $K/Module.symvers ] || cp $K/vmlinux.symvers $K/Module.symvers

rm -rf /tmp/mod /tmp/rootfs && mkdir /tmp/mod /tmp/rootfs
cp -r /src/. /tmp/mod/ && cd /tmp/mod
rm -f web/index.html.gz ./*.o ./*.ko
make KDIR=$K 2>&1 | grep -E "warning|error|WARNING|ERROR|LD \[M\]" || true
test -f netfb.ko

cd /tmp/rootfs
mkdir -p bin dev proc sys
cp /bin/busybox bin/busybox
cp /tmp/mod/netfb.ko netfb.ko
gcc -O2 -Wall -static -o fbtest /src/test/guest/fbtest.c
cp /src/test/guest/init init
cp /src/test/guest/init-demo init-demo
find . | cpio -o -H newc --quiet | gzip -9 > /out/initramfs.cpio.gz
cp $K/arch/arm64/boot/Image /out/Image
ls -la /out
