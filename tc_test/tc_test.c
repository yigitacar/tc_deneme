#include "tc_test.h"

#include <bcc/proto.h>
#include <linux/pkt_cls.h>


int socket_filter(struct __sk_buff *skb) {
    if (!is_icmp_ping_request((void *)(long)skb->data, (void *)(long)skb->data_end)) {
        return 0; // Not an ICMP ping request
    }

    // Log the detection
    bpf_trace_printk("ICMP ping request detected\\n");

    return -1;
}

