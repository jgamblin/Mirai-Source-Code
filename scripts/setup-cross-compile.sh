#!/bin/bash

if [ "$(id -u)" != "0" ]; then
   echo "This script must be run as root" 1>&2
   exit 1
fi

echo -n "Install mysql-server and mysql-client (y/n)? "
old_stty_cfg=$(stty -g)
stty raw -echo
answer=$( while ! head -c 1 | grep -i '[ny]' ;do true ;done )
stty $old_stty_cfg
if echo "$answer" | grep -iq "^y" ;then
    echo "Installing mysql..."
    apt-get install -y mysql-server mysql-client git
fi

echo -e "\nInstalling gcc, golang, electric-fence..."
apt-get install -y gcc golang electric-fence

echo "Creating folder /etc/xcompile"
mkdir /etc/xcompile > /dev/null 2>&1
cd /etc/xcompile

wget https://www.uclibc.org/downloads/binaries/0.9.30.1/cross-compiler-armv4l.tar.bz2
wget https://www.uclibc.org/downloads/binaries/0.9.30.1/cross-compiler-armv5l.tar.bz2
wget http://distro.ibiblio.org/slitaz/sources/packages/c/cross-compiler-armv6l.tar.bz2
wget https://www.uclibc.org/downloads/binaries/0.9.30.1/cross-compiler-i586.tar.bz2
wget https://www.uclibc.org/downloads/binaries/0.9.30.1/cross-compiler-m68k.tar.bz2
wget https://www.uclibc.org/downloads/binaries/0.9.30.1/cross-compiler-mips.tar.bz2
wget https://www.uclibc.org/downloads/binaries/0.9.30.1/cross-compiler-mipsel.tar.bz2
wget https://www.uclibc.org/downloads/binaries/0.9.30.1/cross-compiler-powerpc.tar.bz2
wget https://www.uclibc.org/downloads/binaries/0.9.30.1/cross-compiler-sh4.tar.bz2
wget https://www.uclibc.org/downloads/binaries/0.9.30.1/cross-compiler-sparc.tar.bz2
wget https://www.uclibc.org/downloads/binaries/0.9.30.1/cross-compiler-i686.tar.bz2

echo "extracting..."
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
tar -jxf cross-compiler-i686.tar.bz2

echo "removing all tar.bz2 from /etc/xcompile ..."
rm *.tar.bz2

echo "rename folders..."
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
mv cross-compiler-i686 i686

echo "Editing /etc/environment ..."
sed -e 's|PATH="\(.*\)"|PATH="/etc/xcompile/armv4l/bin:/etc/xcompile/armv5l/bin:/etc/xcompile/armv6l/bin:/etc/xcompile/i586/bin:/etc/xcompile/m68k/bin:/etc/xcompile/mips/bin:/etc/xcompile/mipsel/bin:/etc/xcompile/powerpc/bin:/etc/xcompile/powerpc-440fp/bin:/etc/xcompile/sh4/bin:/etc/xcompile/sparc/bin:/etc/xcompile/i686/bin:\1"|g' -i /etc/environment

GO_ROOT=% go env GOROOT

cd "$GO_ROOT"/src
mkdir github.com
cd github.com
mkdir go-sql-driver
cd go-sql-driver

echo "Getting go-sql-driver ..."
git clone https://github.com/go-sql-driver/mysql.git

cd ..
mkdir mattn
cd mattn

echo "Getting go-shellwords ..."
git clone https://github.com/mattn/go-shellwords.git

echo "Setup cross compiler finished"
echo "Resquest reboot or restart your session"
