#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#define MAX_INTERFACE 16

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, MAX_INTERFACE);
} interface_map SEC(".maps");

// SEC("tc");

/*
int tc_distribute(struct __sk_buff *skb) {
    for(__u32 i = 0; i < MAX_INTERFACE; i++) {
        __u32 *out_ifindex = bpf_map_lookup_elem(&interface_map, &i);

        if(!out_ifindex) {
            bpf_printk("interface_map[%d] is null\n", i);
        }
        else {
            bpf_printk("interface_map[%d] = %u\n", i, *out_ifindex);
        }
        return bpf_clone_redirect(skb, out_ifindex);
    }
    return TC_ACT_OK;
}
*/
