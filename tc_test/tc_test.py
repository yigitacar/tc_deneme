#!/usr/bin/python3
from bcc import BPF
import socket
import os
from time import sleep
from pyroute2 import IPRoute

b = BPF(src_file="tc_test.c")

## get available interfaces
ipr = IPRoute()
links = ipr.get_links()
available_interfaces = []

## TODO: find a way to filter the interfaces and only include the ones of interest
## create a list of available interfaces
for link in links:
    ifname = link.get_attr("IFLA_IFNAME")
    if ifname and ifname != "lo":
        ifindex = link["index"]
        available_interfaces.append(ifname)

## create a map of interfaces and feed to ebpf program
for i, ifindex in enumerate(available_interfaces):
    b["interface_map"][i] = ifindex

print("Available interfaces:", available_interfaces)
print("Interface map:", b)

b.trace_print()

