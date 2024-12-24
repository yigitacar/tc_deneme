#!/bin/bash

clang -O2 -g -target bpf -c tc_kern.c -o tc_kern.o
bpftool gen skeleton tc_kern.o > tc_kern.skel.h
gcc -o tc_userspace tc_userspace.c -lbpf
./tc_userspace