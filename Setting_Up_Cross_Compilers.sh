#!/bin/bash
# RUN ALL OF THESE AS A PRIVELEGED USER, SINCE WE ARE DOWNLOADING INTO /etc

apt-get install -y gcc golang electric-fence

if [ ! -d "/etc/xcompile" ]; then
    pushd .
    mkdir /etc/xcompile
    cd /etc/xcompile

    echo "downloading cross compilers"
    wget --quiet https://www.uclibc.org/downloads/binaries/0.9.30.1/cross-compiler-armv4l.tar.bz2
    wget --quiet https://www.uclibc.org/downloads/binaries/0.9.30.1/cross-compiler-armv5l.tar.bz2
    wget --quiet https://www.uclibc.org/downloads/binaries/0.9.30.1/cross-compiler-i586.tar.bz2
    wget --quiet https://www.uclibc.org/downloads/binaries/0.9.30.1/cross-compiler-m68k.tar.bz2
    wget --quiet https://www.uclibc.org/downloads/binaries/0.9.30.1/cross-compiler-mips.tar.bz2
    wget --quiet https://www.uclibc.org/downloads/binaries/0.9.30.1/cross-compiler-mipsel.tar.bz2
    wget --quiet https://www.uclibc.org/downloads/binaries/0.9.30.1/cross-compiler-powerpc.tar.bz2
    wget --quiet https://www.uclibc.org/downloads/binaries/0.9.30.1/cross-compiler-sh4.tar.bz2
    wget --quiet https://www.uclibc.org/downloads/binaries/0.9.30.1/cross-compiler-sparc.tar.bz2

    echo "unpacking cross compilers"
    tar -jxf cross-compiler-armv4l.tar.bz2
    tar -jxf cross-compiler-armv5l.tar.bz2
    tar -jxf cross-compiler-i586.tar.bz2
    tar -jxf cross-compiler-m68k.tar.bz2
    tar -jxf cross-compiler-mips.tar.bz2
    tar -jxf cross-compiler-mipsel.tar.bz2
    tar -jxf cross-compiler-powerpc.tar.bz2
    tar -jxf cross-compiler-sh4.tar.bz2
    tar -jxf cross-compiler-sparc.tar.bz2

    echo "deleting cross compilers"
    rm *.tar.bz2
    mv cross-compiler-armv4l armv4l
    mv cross-compiler-armv5l armv5l
    mv cross-compiler-i586 i586
    mv cross-compiler-m68k m68k
    mv cross-compiler-mips mips
    mv cross-compiler-mipsel mipsel
    mv cross-compiler-powerpc powerpc
    mv cross-compiler-sh4 sh4
    mv cross-compiler-sparc sparc

    popd
fi


# PUT THESE COMMANDS IN THE FILE ~/.bashrc

# Cross compiler toolchains
echo 'adding compiler toolchains to $PATH'
echo '
export PATH=$PATH:/etc/xcompile/armv4l/bin
export PATH=$PATH:/etc/xcompile/armv5l/bin
export PATH=$PATH:/etc/xcompile/i586/bin
export PATH=$PATH:/etc/xcompile/m68k/bin
export PATH=$PATH:/etc/xcompile/mips/bin
export PATH=$PATH:/etc/xcompile/mipsel/bin
export PATH=$PATH:/etc/xcompile/powerpc/bin
export PATH=$PATH:/etc/xcompile/powerpc-440fp/bin
export PATH=$PATH:/etc/xcompile/sh4/bin
export PATH=$PATH:/etc/xcompile/sparc/bin

# Golang
export PATH=$PATH:/usr/local/go/bin
export GOPATH=$HOME/Documents/go
' >> /etc/bash.bashrc
