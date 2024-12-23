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

char LICENSE[] SEC("license") = "GPL";