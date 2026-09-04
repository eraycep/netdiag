#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include "tcp_connect.h"

#define AF_INET 2
#define AF_INET6 10

#define TCP_ESTABLISHED 1
#define TCP_SYN_SENT 2
#define TCP_CLOSE 7
#define IPPROTO_TCP 6


const volatile u64 target_min_us = 0;
const volatile pid_t target_tgid = 0;

struct connect_start {
    char comm[TASK_COMM_LEN];
    u64 ts;
    u32 tgid;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, struct sock *);
    __type(value, struct connect_start);
} tcp_connect_starts SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 7);
    __type(key, __u32);
    __type(value, __u64);
} tcp_connect_latency_buckets SEC(".maps");

static int trace_connect(struct sock *sk)
{
    u32 tgid = bpf_get_current_pid_tgid() >> 32;
    struct connect_start start = {};

    if (target_tgid && tgid != target_tgid)
        return 0;

    bpf_get_current_comm(&start.comm, sizeof(start.comm));
    start.ts = bpf_ktime_get_ns();
    start.tgid = tgid;
    bpf_map_update_elem(&tcp_connect_starts, &sk, &start, 0);
    return 0;
}

SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(tcp_v4_connect, struct sock *sk)
{
    return trace_connect(sk);
}

SEC("kprobe/tcp_v6_connect")
int BPF_KPROBE(tcp_v6_connect, struct sock *sk)
{
    return trace_connect(sk);
}

__u32 connect_latency_bucket(__u64 delta_ts);

SEC("tracepoint/sock/inet_sock_set_state")
int handle_set_state(struct trace_event_raw_inet_sock_set_state *ctx)
{
    struct sock *sk = (struct sock *)ctx->skaddr;

    if (ctx->protocol != IPPROTO_TCP)
        return 0;

    if (ctx->newstate != TCP_ESTABLISHED)
        return 0;

    struct connect_start *start = bpf_map_lookup_elem(&tcp_connect_starts, &sk);
    if (!start)
        return 0;

    __u64 delta_ts = (bpf_ktime_get_ns() - start->ts) / 1000;
    __u32 bucket = connect_latency_buckets(delta_ts);
    __u64 *count = bpf_map_lookup_elem(&tcp_connect_latency_buckets, &bucket);
    if (count) {
        __sync_fetch_and_add(count, 1);
    }

    bpf_map_delete_elem(&tcp_connect_starts, &sk);
}

__u32 connect_latency_bucket(__u64 delta_ts) {
    return 0;
}