#include "tc_test.h"
#define MAX_INTERFACE 16

struct {
    uint(type, BPF_MAP_TYPE_ARRAY);
    uint(max_entries, MAX_INTERFACE);
    type(key, u32);
    type(value, u32);
} interface_map SEC(".maps");

/*
SEC("tc");

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

//bpf_clone_redirect(skb, ifindex);
int tc_ack(struct __sk_buff *skb) {
//  bpf_trace_printk("[tc] ingress got packet\n");

  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;

  if (is_icmp_ping_request(data, data_end)) {
    struct iphdr *iph = data + sizeof(struct ethhdr);
    struct icmphdr *icmp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
    bpf_trace_printk("[tc] ICMP request for %x type %x\n", iph->daddr,
                     icmp->type);
    return TC_ACT_OK;
  }
  return TC_ACT_SHOT;
}

// Redirects the packet to a chosen interface, could use clone_redirect instead
// 0 gives the index of chosen interface
// a third input parameter could have been used if it was egress
// bpf_redirect(*out_ifindex, 0);