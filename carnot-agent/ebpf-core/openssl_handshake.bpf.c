// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

// Event types
#define EVT_SNI_SET 1
#define EVT_GROUPS_SET 2
#define EVT_HANDSHAKE_RET 3

struct handshake_event_t {
    __u64 ts_ns;
    __u32 pid;
    __u32 tid; // added thread id (lower 32 bits of pid_tgid)
    __u64 ssl_ptr;
    __u8  evt_type; // one of EVT_*
    __u8  success;  // only valid for HANDSHAKE_RET
    char  payload[128]; // sni or groups csv (best-effort, truncated)
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16MB
} handshake_events SEC(".maps");

static __always_inline int emit_event(__u8 evt_type, void *ssl, const char *src) {
    struct handshake_event_t *e = bpf_ringbuf_reserve(&handshake_events, sizeof(*e), 0);
    if (!e) return 0;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    e->ts_ns = bpf_ktime_get_ns();
    e->pid = pid_tgid >> 32;
    e->tid = (__u32)pid_tgid; // set tid
    e->ssl_ptr = (unsigned long)ssl;
    e->evt_type = evt_type;
    e->success = 0;
    if (src) {
        #pragma unroll
        for (int i = 0; i < (int)sizeof(e->payload) - 1; i++) {
            char c = 0;
            if (bpf_core_read(&c, sizeof(c), (const void *)(src + i)) < 0) break;
            e->payload[i] = c;
            if (c == '\0') break;
        }
        e->payload[sizeof(e->payload)-1] = '\0';
    } else {
        e->payload[0] = '\0';
    }
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Probe: SSL_set_tlsext_host_name(SSL *ssl, const char *name)
SEC("uprobe/SSL_set_tlsext_host_name")
int BPF_KPROBE(uprobe_ssl_set_sni, void *ssl, const char *name) {
    if (!ssl || !name) return 0;
    emit_event(EVT_SNI_SET, ssl, name);
    return 0;
}

// Probe: SSL_CTX_set1_groups_list(SSL_CTX *ctx, const char *groups)
SEC("uprobe/SSL_CTX_set1_groups_list")
int BPF_KPROBE(uprobe_ssl_ctx_set1_groups_list, void *ctx, const char *groups) {
    if (!ctx || !groups) return 0;
    emit_event(EVT_GROUPS_SET, ctx, groups);
    return 0;
}

// We capture return of SSL_do_handshake(SSL *ssl)
SEC("uretprobe/SSL_do_handshake")
int BPF_KRETPROBE(uretprobe_ssl_do_handshake, int ret) {
    // Try to get first arg (SSL *). On some ABIs, stored on stack/frame; we rely on BPF_CORE_READ from regs
    void *ssl = (void *)PT_REGS_PARM1(ctx);
    struct handshake_event_t *e = bpf_ringbuf_reserve(&handshake_events, sizeof(*e), 0);
    if (!e) return 0;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    e->ts_ns = bpf_ktime_get_ns();
    e->pid = pid_tgid >> 32;
    e->tid = (__u32)pid_tgid;
    e->ssl_ptr = (unsigned long)ssl;
    e->evt_type = EVT_HANDSHAKE_RET;
    e->success = ret == 1; // OpenSSL returns 1 on success
    e->payload[0] = '\0';
    bpf_ringbuf_submit(e, 0);
    return 0;
}
