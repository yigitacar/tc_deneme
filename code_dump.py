## The following defines an event called syscall that is triggered when
## the program enters the function execve, then it attaches this event to
## program called hello world
# syscall = b.get_syscall_fnname("execve")
# b.attach_kprobe(event=syscall, fn_name="hello_world")