#!/bin/sh

cd bin
gcc -fPIC -ljson-c -c ../src/pampam.c
ld -x -lpam -ljson-c --shared -o ../bin/pampam.so ../bin/pampam.o

