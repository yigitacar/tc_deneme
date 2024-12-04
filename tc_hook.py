## For user space behavior
from bcc import BPF
from time import sleep
from pyroute2 import IPRoute

## Initialize the BPF object
b = BPF(src_file="tc_hook.c")


# TODO define a function in C and enter the name below
f = b.load_func(func_name="fn_name", prog_type=BPF.SCHED_CLS)
interface = "eth0"

ipr = IPRoute()
links = ipr.link_lookup(ifname=interface)
idx = links[0]
ipr.tc(command="add", kind="egress", index=idx, handle=0)

## The following defines an event called syscall that is triggered when
## the program enters the function execve, then it attaches this event to
## program called hello world
# syscall = b.get_syscall_fnname("execve")
# b.attach_kprobe(event=syscall, fn_name="hello_world")
