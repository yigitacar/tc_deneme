#include <linux/icmp.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>
#include <linux/in.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define MAX_INTERFACE 10

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, MAX_INTERFACE);
} interface_map SEC(".maps");

SEC("classifier")
int tc_egress_multiplicate(struct __sk_buff *skb) {
    __u32 key = 0;
    __u32 *ifindex;

    // Loop through all entries in the interface_map
    for (key = 0; key < MAX_INTERFACE; key++) {
        ifindex = bpf_map_lookup_elem(&interface_map, &key);
        if (ifindex && *ifindex > 0) {
            // Redirect the packet to the interface specified in the map
            bpf_clone_redirect(skb, *ifindex, 0);
        }
    }

    // Drop the original packet after cloning (optional)
    //return TC_ACT_SHOT;
	return 1;
}

char LICENSE[] SEC("license") = "GPL";