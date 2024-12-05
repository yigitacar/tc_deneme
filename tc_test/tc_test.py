#!/usr/bin/python3
from bcc import BPF
import socket
import os
from time import sleep
from pyroute2 import IPRoute

b = BPF(src_file="tc_test.c")


interface = "ens3"

f = b.load_func("socket_filter", BPF.SOCKET_FILTER)
BPF.attach_raw_socket(f, interface)

fd = f.sock
sock = socket.fromfd(fd, socket.PF_PACKET, socket.SOCK_RAW, socket.IPPROTO_IP)
sock.setblocking(True)

b.trace_print()

