#!/bin/bash

sudo su

echo -n "Install mysql-server and mysql-client (y/n)? "
old_stty_cfg=$(stty -g)
stty raw -echo
answer=$( while ! head -c 1 | grep -i '[ny]' ;do true ;done )
stty $old_stty_cfg
if echo "$answer" | grep -iq "^y" ;then
    apt-get install mysql-server mysql-client
fi

apt-get install gcc golang electric-fence
mkdir /etc/xcompile

cp ../cross-compiler-armv4l.tar.bz2 /etc/xcompile/cross-compiler-armv4l.tar.bz2
cp ../cross-compiler-armv5l.tar.bz2 /etc/xcompile/cross-compiler-armv5l.tar.bz2
cp ../cross-compiler-armv6l.tar.bz2 /etc/xcompile/cross-compiler-armv6l.tar.bz2
cp ../cross-compiler-i586.tar.bz2 /etc/xcompile/cross-compiler-i586.tar.bz2
cp ../cross-compiler-m68k.tar.bz2 /etc/xcompile/cross-compiler-m68k.tar.bz2
cp ../cross-compiler-mips.tar.bz2 /etc/xcompile/cross-compiler-mips.tar.bz2
cp ../cross-compiler-mipsel.tar.bz2 /etc/xcompile/cross-compiler-mipsel.tar.bz2
cp ../cross-compiler-powerpc.tar.bz2 /etc/xcompile/cross-compiler-powerpc.tar.bz2
cp ../cross-compiler-sh4.tar.bz2 /etc/xcompile/cross-compiler-sh4.tar.bz2
cp ../cross-compiler-sparc.tar.bz2 /etc/xcompile/cross-compiler-sparc.tar.bz2

cd /etc/xcompile

tar -jxf cross-compiler-armv4l.tar.bz2
tar -jxf cross-compiler-armv5l.tar.bz2
tar -jxf cross-compiler-armv6l.tar.bz2
tar -jxf cross-compiler-i586.tar.bz2
tar -jxf cross-compiler-m68k.tar.bz2
tar -jxf cross-compiler-mips.tar.bz2
tar -jxf cross-compiler-mipsel.tar.bz2
tar -jxf cross-compiler-powerpc.tar.bz2
tar -jxf cross-compiler-sh4.tar.bz2
tar -jxf cross-compiler-sparc.tar.bz2

rm *.tar.bz2
mv cross-compiler-armv4l armv4l
mv cross-compiler-armv5l armv5l
mv cross-compiler-armv6l armv6l
mv cross-compiler-i586 i586
mv cross-compiler-m68k m68k
mv cross-compiler-mips mips
mv cross-compiler-mipsel mipsel
mv cross-compiler-powerpc powerpc
mv cross-compiler-sh4 sh4
mv cross-compiler-sparc sparc

exit

export PATH=$PATH:/etc/xcompile/armv4l/bin
export PATH=$PATH:/etc/xcompile/armv5l/bin
export PATH=$PATH:/etc/xcompile/armv6l/bin
export PATH=$PATH:/etc/xcompile/i586/bin
export PATH=$PATH:/etc/xcompile/m68k/bin
export PATH=$PATH:/etc/xcompile/mips/bin
export PATH=$PATH:/etc/xcompile/mipsel/bin
export PATH=$PATH:/etc/xcompile/powerpc/bin
export PATH=$PATH:/etc/xcompile/powerpc-440fp/bin
export PATH=$PATH:/etc/xcompile/sh4/bin
export PATH=$PATH:/etc/xcompile/sparc/bin
