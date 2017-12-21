#!/bin/sh
script_dir=$(cd $(dirname $0); pwd) || exit
cd $script_dir

compile()
{
    echo 
    echo "[*] compiling $1.bin"
    nasm -f bin -o $1.bin $1.nasm
    ndisasm -b64 $1.bin > $1.disasm
    cat $1.disasm
    grep _start $1.nasm > /dev/null || return
    echo 
    echo "[*] compiling $1.elf"
    nasm -f elf64 -o $1.o $1.nasm
    ld $1.o -o $1.elf
    nm $1.elf > $1.syms
    objdump -Mintel -d $1.elf > $1.s
    cat $1.s
}

compile small-code
compile with-branch
compile correct-argv1