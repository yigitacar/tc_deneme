## For user space behavior
from bcc import BPF
from time import sleep
from pyroute2 import IPRoute

## Initialize the BPF object
b = BPF(src_file="tc_hook.c")

# TODO: define a function in C and enter the name below
f = b.load_func(func_name="tc_dist", prog_type=BPF.SCHED_CLS)

# TODO: use properties in iproute2 library to find available interfaces
interface = "ens3"

ipr = IPRoute()
links = ipr.link_lookup(ifname=interface)
idx = links[0]

## The special handle ffff:0 is reserved for the ingress qdisc.
try:
    # handle could be :1 instead
    ipr.tc(command="add-filter", kind="egress", index=idx, handle="1:")
except:
    print("qdisc already exists")


