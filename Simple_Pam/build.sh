#!/bin/sh

cd bin
gcc -fPIC -c ../src/pampam.c
ld -x --shared -o ../bin/pampam.so ../bin/pampam.o

