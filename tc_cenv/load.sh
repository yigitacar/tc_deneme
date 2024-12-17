#!/bin/bash

clang -O2 -g -target bpf -c redirect_egress.c -o redirect_egress.o
gcc -o load_redirect load_redirect.c -lbpf
./load_redirect