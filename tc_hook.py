## For user space behavior
from bcc import BPF
from time import sleep
from pyroute2 import IPRoute as ip

b = BPF(src_file="tc_hook.c")

# TODO define a function in C and enter the name below
f = b.load_func("fn_name", BPF.SCHED_CLS)

interface = "eth0"