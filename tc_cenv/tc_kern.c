#include <linux/pkt_cls.h>
#include <linux/pkt_sched.h>
#include <linux/in.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define MAX_INTERFACE 10

int tc_egress_multiplicate(struct __sk_buff *skb);

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, MAX_INTERFACE);
} interface_map SEC(".maps");

SEC("classifier")
//SEC("tc")
int tc_egress_multiplicate(struct __sk_buff *skb) {
    __u32 key = 0;
    __u32 *ifindex;
	
    // Loop through all entries in the interface_map
    for (int i = 0; i < MAX_INTERFACE; i++) {
        ifindex = bpf_map_lookup_elem(&interface_map, &key);
		
		//bpf_printk("interface: %u \n", ifindex);
		
		if (!ifindex)
			continue;
        if (ifindex && *ifindex > 0) {
            // Redirect the packet to the interface specified in the map
            bpf_clone_redirect(skb, *ifindex, 0);
        }
		key++;
    }

    // Drop the original packet after cloning (optional)
    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";