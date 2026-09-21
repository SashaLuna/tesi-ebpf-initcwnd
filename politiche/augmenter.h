#ifndef __AUGMENTER_H
#define __AUGMENTER_H

/* Header condiviso kernel/user-space: la struct è il VALORE della mappa,
 * quindi il layout deve essere identico sui due lati. */
struct aug_stats {
    __u32 cwnd;      /* ultima snd_cwnd osservata (pacchetti) */
    __u32 srtt_us;   /* smoothed RTT in microsecondi */
    __u32 retrans;   /* total_retrans del socket */
    __u32 dst_ip;    /* IPv4 del client, in ordine di host */
    __u32 iw;        /* finestra iniziale effettivamente applicata */
    __u32 iw_route;     /* finestra della route, PRIMA dell'intervento */
    __u32 min_rtt_us;   /* minimo filtrato del RTT */
    __u32 mss;          /* mss_cache: converte i segmenti in byte */
    __u64 bytes_acked;  /* byte confermati: controllo che l'oggetto sia passato */
    __u64 t_open_ns;    /* istante dell'apertura, orologio monotono */
    __u64 t_close_ns;   /* istante della chiusura */
    __u16 dport;        /* porta effimera del CLIENT: è la chiave con cui la
                         * riga si congiunge a quella misurata lato client
                         * (curl %{local_port}) */

    __u16 sport;        /* porta del server */
    __u8  emitted;      /* guardia: un solo record per connessione */
};

#endif