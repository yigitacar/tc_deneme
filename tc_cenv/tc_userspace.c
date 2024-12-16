#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <net/if.h>

#define IFACE "ens3" // Replace with your network interface
#define BPF_PROG_PATH "/path/to/your/tc_program.o" // Path to your compiled eBPF program

int main() {
    struct bpf_object *obj;
    int prog_fd, ifindex;
    int ret;
    struct bpf_tc_hook hook = {};
    struct bpf_tc_opts opts = {};

    // Load the eBPF object file
    obj = bpf_object__open_file(BPF_PROG_PATH, NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Failed to open eBPF object: %s\n", strerror(-libbpf_get_error(obj)));
        return 1;
    }

    // Load the program into the kernel
    ret = bpf_object__load(obj);
    if (ret) {
        fprintf(stderr, "Failed to load eBPF object: %s\n", strerror(-ret));
        bpf_object__close(obj);
        return 1;
    }

    // Get the file descriptor of the eBPF program
    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "tc_egress_prog"); // Replace with your program's name
    if (!prog) {
        fprintf(stderr, "Failed to find eBPF program by name\n");
        bpf_object__close(obj);
        return 1;
    }

    prog_fd = bpf_program__fd(prog);
    if (prog_fd < 0) {
        fprintf(stderr, "Failed to get file descriptor for eBPF program\n");
        bpf_object__close(obj);
        return 1;
    }

    // Get the interface index
    ifindex = if_nametoindex(IFACE);
    if (!ifindex) {
        fprintf(stderr, "Failed to get interface index for %s: %s\n", IFACE, strerror(errno));
        bpf_object__close(obj);
        return 1;
    }

    // Set up the tc hook
    hook.ifindex = ifindex;
    hook.attach_point = BPF_TC_EGRESS; // Change to BPF_TC_INGRESS for ingress hook

    ret = bpf_tc_hook_create(&hook);
    if (ret && ret != -EEXIST) {
        fprintf(stderr, "Failed to create tc hook: %s\n", strerror(-ret));
        bpf_object__close(obj);
        return 1;
    }

    // Attach the eBPF program
    memset(&opts, 0, sizeof(opts));
    opts.handle = 1;
    opts.priority = 1;
    opts.prog_fd = prog_fd;

    ret = bpf_tc_attach(&hook, &opts);
    if (ret) {
        fprintf(stderr, "Failed to attach eBPF program: %s\n", strerror(-ret));
        bpf_tc_hook_destroy(&hook);
        bpf_object__close(obj);
        return 1;
    }

    printf("eBPF program successfully attached to %s\n", IFACE);

    // Keep the program running
    printf("Press Ctrl+C to detach and exit...\n");
    while (1) {
        sleep(1);
    }

    // Clean up
    ret = bpf_tc_detach(&hook, &opts);
    if (ret) {
        fprintf(stderr, "Failed to detach eBPF program: %s\n", strerror(-ret));
    }

    ret = bpf_tc_hook_destroy(&hook);
    if (ret) {
        fprintf(stderr, "Failed to destroy tc hook: %s\n", strerror(-ret));
    }

    bpf_object__close(obj);
    return 0;
}
