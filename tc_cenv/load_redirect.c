#include <bpf/libbpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <net/if.h>

#define MAX_INTERFACE 10

int main(int argc, char **argv) {
    struct bpf_object *obj;
    struct bpf_map *map;
    int prog_fd, map_fd;
    __u32 key, value;

    // Load the BPF object file
    obj = bpf_object__open_file("redirect_egress.o", NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Error opening BPF object file.\n");
        return 1;
    }

    // Load the program
    if (bpf_object__load(obj)) {
        fprintf(stderr, "Error loading BPF program.\n");
        return 1;
    }

    // Find the map and program
    map = bpf_object__find_map_by_name(obj, "interface_map");
    if (!map) {
        fprintf(stderr, "Error finding interface_map.\n");
        return 1;
    }

    prog_fd = bpf_program__fd(bpf_object__find_program_by_name(obj, "tc_egress_multiplicate"));
    map_fd = bpf_map__fd(map);

    // Attach the BPF program to tc egress
    system("tc qdisc add dev ens3 clsact");
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "tc filter add dev ens3 egress bpf da fd %d", prog_fd);
    system(cmd);

    // Update the interface_map with desired interface indices
    for (key = 0; key < MAX_INTERFACE; key++) {
        value = key + 2; // Example: Use interfaces with indices 2, 3, ..., 11
        if (bpf_map_update_elem(map_fd, &key, &value, BPF_ANY)) {
            fprintf(stderr, "Error updating interface_map at key %u.\n", key);
            return 1;
        }
    }

    printf("BPF program loaded and interfaces configured.\n");
    sleep(60); // Keep the program running for 60 seconds
    return 0;
}
