#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include "tcp_connect.h"

#define AF_INET 2
#define AF_INET6 10

const volatile u64 target_min_us = 0;
const volatile pid_t target_tgid = 0;

struct piddata {
    char comm[TASK_COMM_LEN];
    u64 ts;
    u32 tgid;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct sock *);
    __type(value, struct piddata);
} start SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct sock *);
    __type(value, u32);
} completion SEC(".maps");

static int trace_connect(struct sock *sk)
{
    u32 tgid = bpf_get_current_pid_tgid() >> 32;
    struct piddata piddata = {};

    if (target_tgid && tgid != target_tgid)
        return 0;

    bpf_get_current_comm(&piddata.comm, sizeof(piddata.comm));
    piddata.ts = bpf_ktime_get_ns();
    piddata.tgid = tgid;
    bpf_map_update_elem(&start, &sk, &piddata, 0);
    return 0;
}

SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(tcp_v4_connect, struct sock *sk)
{
    return trace_connect(sk);
}

SEC("tracepoint/sock/inet_sock_set_state")
int handle_set_state(struct trace_event_raw_inet_sock_set_state *ctx)
{
    
}