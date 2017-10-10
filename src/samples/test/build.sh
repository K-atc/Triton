#!/bin/sh
script_dir=$(cd $(dirname $BASH_SOURCE); pwd)
cd $script_dir

compile()
{
    echo "[*] compiling $1"
    nasm -f bin -o $1.bin $1.nasm
    nasm -f elf64 -o $1.elf $1.nasm
    ndisasm -b64 $1.bin > $1.disasm
    cat $1.disasm
}

compile small-code
compile with-branch