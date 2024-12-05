#!/usr/bin/python3
from bcc import BPF
import socket
import os
from time import sleep
from pyroute2 import IPRoute

b = BPF(src_file="tc_test.c")
interface = "ens4"

ipr = IPRoute()
links = ipr.link_lookup(ifname=interface)
idx = links[0]

try:
    ipr.tc("add", "egress", idx, ":1")
except:
    print("qdisc ingress already exists")

fi = b.load_func("tc_ack", BPF.SCHED_CLS)

ipr.tc("add-filter", "bpf", idx, ":1", fd=fi.fd,
        name=fi.name, parent="ffff:", action="ok", classid=1, da=True)

b.trace_print()

