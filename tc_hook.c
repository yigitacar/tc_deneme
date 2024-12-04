// For eBPF behavior
#include "tc_hook.h"

#include <bcc/proto.h>
#include <linux/pkt_cls.h>

int tc_dist(struct __sk_buff *skb) {
    bpf_trace_printk("tv off!");
    return 0;
}
