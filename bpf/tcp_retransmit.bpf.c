#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define AF_INET 2
#define AF_INET6 10

struct flow_key_ipv4 {
	__u32 saddr;
	__u32 daddr;
	__u16 sport;
	__u16 dport;
};

struct flow_key_ipv6 {
    __u8 saddr[16];
    __u8 daddr[16];
	__u16 sport;
	__u16 dport;
};

struct netdiag_flow_stats {
	__u64 retransmits;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, struct flow_key_ipv4);
	__type(value, struct netdiag_flow_stats);
} tcp_retransmit_flows_ipv4 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, struct flow_key_ipv6);
	__type(value, struct netdiag_flow_stats);
} tcp_retransmit_flows_ipv6 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} retransmit_count SEC(".maps");

static __always_inline void count_tcp_retransmit_ipv6(struct trace_event_raw_tcp_event_sk_skb *skb);
static __always_inline void count_tcp_retransmit_ipv4(struct trace_event_raw_tcp_event_sk_skb *skb);

SEC("tracepoint/tcp/tcp_retransmit_skb")
int count_tcp_retransmit(struct trace_event_raw_tcp_event_sk_skb *skb)
{
	__u32 key = 0;
	__u64 *count = bpf_map_lookup_elem(&retransmit_count, &key);
	__u16 family = 0;

	if (count)
		__sync_fetch_and_add(count, 1);

	BPF_CORE_READ_INTO(&family, skb, family);

	if (family == AF_INET) {
		count_tcp_retransmit_ipv4(skb);
	} else if (family == AF_INET6) {
		count_tcp_retransmit_ipv6(skb);
	}

	return 0;
}

static __always_inline void count_tcp_retransmit_ipv4(struct trace_event_raw_tcp_event_sk_skb *skb) {
	struct flow_key_ipv4 flow_key = {};
	struct netdiag_flow_stats initial = {
		.retransmits = 1,
	};

	BPF_CORE_READ_INTO(&flow_key.saddr, skb, saddr);
	BPF_CORE_READ_INTO(&flow_key.daddr, skb, daddr);
	BPF_CORE_READ_INTO(&flow_key.sport, skb, sport);
	BPF_CORE_READ_INTO(&flow_key.dport, skb, dport);

	struct netdiag_flow_stats *stats = bpf_map_lookup_elem(&tcp_retransmit_flows_ipv4, &flow_key);

	if (stats) {
		__sync_fetch_and_add(&stats->retransmits, 1);
	} else {
		bpf_map_update_elem(&tcp_retransmit_flows_ipv4, &flow_key, &initial, BPF_NOEXIST);
	}
}

static __always_inline void count_tcp_retransmit_ipv6(struct trace_event_raw_tcp_event_sk_skb *skb) {
	struct flow_key_ipv6 flow_key = {};
	struct netdiag_flow_stats initial = {
		.retransmits = 1,
	};

	BPF_CORE_READ_INTO(&flow_key.saddr, skb, saddr_v6);
	BPF_CORE_READ_INTO(&flow_key.daddr, skb, daddr_v6);
	BPF_CORE_READ_INTO(&flow_key.sport, skb, sport);
	BPF_CORE_READ_INTO(&flow_key.dport, skb, dport);

	struct netdiag_flow_stats *stats = bpf_map_lookup_elem(&tcp_retransmit_flows_ipv6, &flow_key);

	if (stats) {
		__sync_fetch_and_add(&stats->retransmits, 1);
	} else {
		bpf_map_update_elem(&tcp_retransmit_flows_ipv6, &flow_key, &initial, BPF_NOEXIST);
	}
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
