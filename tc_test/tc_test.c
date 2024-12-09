#include "tc_test.h"

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 16);
    __type(key, __u32);
    __type(value, __u32);
} interface_map SEC(".maps");

SEC("tc");

int tc_distribute(struct __sk_buff *skb) {

// TODO: loop through map elements and clone redirect each (challenge is finding the border)

//bpf_clone_redirect(skb, ifindex);
}

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