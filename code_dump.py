## The following defines an event called syscall that is triggered when
## the program enters the function execve, then it attaches this event to
## program called hello world
# syscall = b.get_syscall_fnname("execve")
# b.attach_kprobe(event=syscall, fn_name="hello_world")


# interface = "ens4"
#
# ipr = IPRoute()
# links = ipr.link_lookup(ifname=interface)
# idx = links[0]
#
# try:
#     ipr.tc("add", "egress", idx, ":1")
# except:
#     print("qdisc ingress already exists")
#
# fi = b.load_func("tc_ack", BPF.SCHED_CLS)
#
# ipr.tc("add-filter", "bpf", idx, ":1", fd=fi.fd,
#         name=fi.name, parent="ffff:", action="ok", classid=1, da=True)