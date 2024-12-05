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

# ipr = IPRoute()
# links = ipr.link_lookup(ifname=interface)
# idx = links[0]

# try:
#     ipr.tc("add", "ingress", idx, "ffff:")
# except:
#     print("qdisc ingress already exists")
#
# fi = b.load_func("tc_pingpong", BPF.SCHED_CLS)
#
# ipr.tc("add-filter", "bpf", idx, ":1", fd=fi.fd,
#         name=fi.name, parent="ffff:", action="ok", classid=1, da=True)

# Remove with sudo tc qdisc del dev docker0 parent ffff:
# (or make clean)

# Read data from socket filter
while True:
  packet_str = os.read(fd, 4096)
  print("Userspace got data: %x", packet_str)


