set -eu
export LC_ALL=C TZ=UTC SOURCE_DATE_EPOCH=0
findmnt /tmp > /out/scratch-mount.txt
gcc --version > /out/compiler.txt
make --version >> /out/compiler.txt
ld --version >> /out/compiler.txt
dpkg-query -W -f='${Package}\t${Version}\n' gcc gcc-12 cpp-12 binutils make libc6 libc6-dev linux-libc-dev libgcc-12-dev > /out/compiler-packages.tsv
sha256sum /usr/bin/x86_64-linux-gnu-gcc-12 /usr/bin/make /usr/bin/x86_64-linux-gnu-ld.bfd /usr/lib/gcc/x86_64-linux-gnu/12/cc1 /usr/lib/x86_64-linux-gnu/libc.so.6 > /out/compiler-sha256.txt
for build in a b; do
    mkdir /tmp/build-$build
    cp -R /source/. /tmp/build-$build/
    cd /tmp/build-$build
    export CFLAGS='-m64 -ffile-prefix-map=/tmp/build-a=/usr/src/argon2 -ffile-prefix-map=/tmp/build-b=/usr/src/argon2'
    make CC=gcc OPTTARGET=generic ARGON2_VERSION=20190702 libargon2.so.1
    if [ "$build" = a ]; then
        make CC=gcc OPTTARGET=generic test > /out/upstream-tests.txt 2>&1
    fi
done
cmp /tmp/build-a/libargon2.so.1 /tmp/build-b/libargon2.so.1
readelf -h -d -V /tmp/build-a/libargon2.so.1 > /out/elf.txt
nm -D --defined-only /tmp/build-a/libargon2.so.1 > /out/exported-symbols.txt
ldd /tmp/build-a/libargon2.so.1 > /out/dynamic-dependencies.txt
install -m 0644 /tmp/build-a/libargon2.so.1 /candidate/libargon2.so
sha256sum /tmp/build-a/libargon2.so.1 /tmp/build-b/libargon2.so.1 /candidate/libargon2.so
