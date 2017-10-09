#!/bin/sh
script_dir=$(cd $(dirname $BASH_SOURCE); pwd)
cd $script_dir

nasm -f bin -o small-code.bin small-code.nasm
nasm -f elf64 -o small-code.elf small-code.nasm
ndisasm -b64 small-code.bin