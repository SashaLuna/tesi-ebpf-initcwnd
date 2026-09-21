#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "augmenter.h"

#ifndef SOL_TCP
#define SOL_TCP 6
#endif

/* Finestra iniziale decisa dallo spazio utente, una voce per destinazione.
 * Qui viene solo letta. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u32);
} iw_map SEC(".maps");

/* Statistiche per connessione. Legate al socket, così il kernel le libera
 * da solo e due connessioni dello stesso client non si sovrascrivono. */
struct {
    __uint(type, BPF_MAP_TYPE_SK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __type(value, struct aug_stats);
} stats_map SEC(".maps");

/* Un record per connessione chiusa, verso lo spazio utente. */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} events SEC(".maps");


/* create=1 solo alla prima osservazione del socket. */
static struct aug_stats *get_stats(struct bpf_sock *sk, int create)
{
    __u64 flags;
    if (create) {
        flags = BPF_SK_STORAGE_GET_F_CREATE;
    } else {
        flags = 0;
    }
    return bpf_sk_storage_get(&stats_map, sk, NULL, flags);
}

static __always_inline void emit_record(struct aug_stats *st)
{
    bpf_ringbuf_output(&events, st, sizeof(*st), 0);
}

SEC("sockops")
int augmenter(struct bpf_sock_ops *skops)
{
    __u32 dst_ip, *val, iw = 0;
    struct aug_stats *st;
    struct bpf_sock *sk = skops->sk;
    struct bpf_tcp_sock *tcp_sk;
    int op = (int)skops->op;

    /* Il verificatore vuole il controllo di nullità esplicito. */
    if (!sk)
        return 0;
    tcp_sk = bpf_tcp_sock(sk);
    if (!tcp_sk)
        return 0;

    dst_ip = bpf_ntohl(skops->remote_ip4);

    switch (op)
    {
    case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
        /* Connessione appena accettata: qui la finestra iniziale è ancora
         * modificabile. I richiami su RTT e stato vanno chiesti, di default
         * non arrivano. */
        bpf_sock_ops_cb_flags_set(skops,
                                  BPF_SOCK_OPS_RTT_CB_FLAG |
                                  BPF_SOCK_OPS_STATE_CB_FLAG);

        st = get_stats(sk, 1);
        if (!st) break;
        st->t_open_ns = bpf_ktime_get_ns();
        st->dst_ip = dst_ip;
        st->dport = (__u16)bpf_ntohl(skops->remote_port);
        st->sport = (__u16)skops->local_port;
        st->iw_route = tcp_sk->snd_cwnd;   /* finestra della route, prima dell'intervento */

        /* Nessuna voce in mappa: si lascia la finestra del kernel. */
        val = bpf_map_lookup_elem(&iw_map, &dst_ip);
        if (val) iw = *val;

        if (iw)
            bpf_setsockopt(skops, SOL_TCP, TCP_BPF_IW, &iw, sizeof(iw));

        /* Rileggo dopo la setsockopt: mi serve la finestra applicata,
         * non quella chiesta. */
        tcp_sk = bpf_tcp_sock(sk);
        if (!tcp_sk) break;
        st->iw = tcp_sk->snd_cwnd;
        st->cwnd = tcp_sk->snd_cwnd;
        break;

    case BPF_SOCK_OPS_STATE_CB:
        st = get_stats(sk, 0);
        if (!st) break;

        if (tcp_sk->snd_cwnd > st->cwnd)
            st->cwnd = tcp_sk->snd_cwnd;

        /* args[1] è il nuovo stato: interessa solo CLOSE. */
        if (skops->args[1] != BPF_TCP_CLOSE)
            break;

        /* Una sola riga per connessione. */
        if (st->emitted) break;
        st->emitted = 1;

        st->srtt_us     = tcp_sk->srtt_us >> 3;   /* srtt_us è in ottavi di microsecondo */
        st->min_rtt_us  = tcp_sk->rtt_min;
        st->retrans     = tcp_sk->total_retrans;
        st->mss         = tcp_sk->mss_cache;
        st->bytes_acked = tcp_sk->bytes_acked;
        st->t_close_ns  = bpf_ktime_get_ns();

        emit_record(st);
        break;

    case BPF_SOCK_OPS_RTT_CB:
        /* Aggiorno a ogni campione, così la cwnd massima è quella vista
         * durante il trasferimento. */
        st = get_stats(sk, 0);
        if (!st) break;

        if (tcp_sk->snd_cwnd > st->cwnd)
            st->cwnd = tcp_sk->snd_cwnd;

        st->srtt_us = tcp_sk->srtt_us >> 3;
        break;

    default:
        break;
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
