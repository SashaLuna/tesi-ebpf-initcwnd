/* augmenter.c - politica «statichigh»: finestra statica alta.
 *
 * Scrive in iw_map lo stesso valore per tutte le destinazioni, passato con
 * --iw e tarato sul banco con «testbed.py calibrate». Con --dst la mappa
 * viene precaricata, così anche la prima connessione parte dalla finestra alta.
 */

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>          /* atoi, strtoul */
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <bpf/libbpf.h>
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include "augmenter.skel.h"
#include "augmenter.h"

static struct {
	const char   *cgroup;
	const char   *csv_path;
	const char   *run_id;
	const char   *policy_label;
	unsigned int  bw_mbit;
	unsigned long obj_bytes;
	unsigned int  iteration;
	unsigned int iw;
	const char *dst_list;
} cfg = {
	.cgroup       = "/sys/fs/cgroup",
	.csv_path     = NULL,
	.run_id       = "run",
	.policy_label = "static10",
	.bw_mbit      = 0,
	.obj_bytes    = 0,
	.iteration    = 0,
	.iw 		  = 0,
	.dst_list	  = NULL,
};

static void parse_args(int argc, char **argv)
{
	int i;
 
	for (i = 1; i < argc; i++) {
		const char *a = argv[i];
		int has_val = (i + 1 < argc);
 
		if      (!strcmp(a, "--cgroup")       && has_val) cfg.cgroup = argv[++i];
		else if (!strcmp(a, "--csv")          && has_val) cfg.csv_path = argv[++i];
		else if (!strcmp(a, "--run-id")       && has_val) cfg.run_id = argv[++i];
		else if (!strcmp(a, "--policy-label") && has_val) cfg.policy_label = argv[++i];
		else if (!strcmp(a, "--bw-mbit")      && has_val) cfg.bw_mbit = atoi(argv[++i]);
		else if (!strcmp(a, "--obj-bytes")    && has_val) cfg.obj_bytes = strtoul(argv[++i], NULL, 10);
		else if (!strcmp(a, "--iteration")    && has_val) cfg.iteration = atoi(argv[++i]);
		else if (!strcmp(a, "--iw")           && has_val) cfg.iw = atoi(argv[++i]);
		else if (!strcmp(a, "--dst")          && has_val) cfg.dst_list = argv[++i];
		else
			fprintf(stderr, "augmenter: opzione ignorata «%s»\n", a);
	}
}

#define MAX_DSTS 256
 
struct dst_state {
	__u32 dst_ip;      /* chiave, ordine di host; 0 = voce libera */
	__u32 samples;     /* connessioni osservate verso questa destinazione */
	__u32 iw_current;  /* ultimo valore scritto in iw_map */
};
 
static struct dst_state dsts[MAX_DSTS];
 
static struct dst_state *dst_lookup(__u32 ip)
{
	int i, libera = -1;
 
	for (i = 0; i < MAX_DSTS; i++) {
		if (dsts[i].dst_ip == ip)
			return &dsts[i];
		if (dsts[i].dst_ip == 0 && libera < 0)
			libera = i;
	}
	if (libera < 0)
		return NULL;
	memset(&dsts[libera], 0, sizeof(dsts[libera]));
	dsts[libera].dst_ip = ip;
	return &dsts[libera];
}
 
/* A livello di file perché lo usa run_analyzer, che è la callback del
 * ring buffer e non riceve main() come contesto. */
static int iw_fd = -1;
 
/* Precaricamento di iw_map dalla lista passata con --dst. */
static int preload_iw_map(void)
{
	char buf[512], *tok, *save = NULL;
	int n = 0;
 
	if (!cfg.dst_list)
		return 0;
 
	snprintf(buf, sizeof(buf), "%s", cfg.dst_list);
 
	for (tok = strtok_r(buf, ",", &save); tok; tok = strtok_r(NULL, ",", &save)) {
		struct dst_state *d;
		struct in_addr a;
		__u32 key, val = cfg.iw;
 
		if (inet_pton(AF_INET, tok, &a) != 1) {
			fprintf(stderr, "augmenter: indirizzo non valido «%s»\n", tok);
			return -1;
		}
 
		/* La chiave di iw_map è in ordine di host: nel kernel viene costruita
		 * con bpf_ntohl(skops->remote_ip4). */
		key = ntohl(a.s_addr);
 
		if (bpf_map_update_elem(iw_fd, &key, &val, BPF_ANY)) {
			fprintf(stderr, "scrittura in iw_map fallita per %s: %s\n",
				tok, strerror(errno));
			return -1;
		}
		d = dst_lookup(key);
		if (d)
			d->iw_current = val;
		n++;
	}
 
	fprintf(stderr, "augmenter: precaricate %d destinazioni con IW=%u\n",
		n, cfg.iw);
	return 0;
}

static FILE *csv;

static const char *CSV_HEADER =
	"run_id,policy,bw_mbit,obj_bytes,iteration,"
	"dst_ip,dport,sport,"
	"iw_route,iw_applied,max_cwnd,srtt_us,min_rtt_us,retrans,"
	"bytes_acked,mss,duration_us,"
	"ewma_after,samples,penalties\n";
 
static int csv_open(void)
{
	if (!cfg.csv_path)
		return 0;
	csv = fopen(cfg.csv_path, "w");
	if (!csv) {
		fprintf(stderr, "apertura di %s fallita: %s\n",
			cfg.csv_path, strerror(errno));
		return -1;
	}
	fputs(CSV_HEADER, csv);
	/* La comparsa del file segnala a chi orchestra la campagna che il
	 * programma è agganciato e i client possono partire. */
	fflush(csv);
	return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level,
			   const char *format, va_list args)
{
	(void)level;
	return vfprintf(stderr, format, args);
}

static volatile sig_atomic_t exiting = 0;

static void sig_handler(int sig)
{
	(void)sig;
	exiting = 1;
}

static int run_analyzer(void *ctx, void *data, size_t len)
{
	struct aug_stats *st = data;
	struct dst_state *d;
    struct in_addr a;

	char ip[INET_ADDRSTRLEN];
	__u32 key, val;

	(void)ctx;
	if (len < sizeof(*st))
		return 0;

	d = dst_lookup(st->dst_ip);
	if (d)
		d->samples++;

	key = st->dst_ip;
	val = cfg.iw;
	if (bpf_map_update_elem(iw_fd, &key, &val, BPF_ANY) == 0) {
		if (d)
			d->iw_current = val;
	} else {
		fprintf(stderr, "scrittura in iw_map fallita: %s\n", strerror(errno));
	}
 
	a.s_addr = htonl(st->dst_ip);
	inet_ntop(AF_INET, &a, ip, sizeof(ip));
 
	printf("analyzer: dst=%s IW %u->%u max_cwnd=%u srtt=%.2f ms retrans=%u\n",
	       ip, st->iw_route, st->iw, st->cwnd,
	       st->srtt_us / 1000.0, st->retrans);
 
	if (csv) {
		a.s_addr = htonl(st->dst_ip);
		/* Le ultime tre colonne restano a zero: questa politica non stima
		 * e non penalizza, e il conteggio dei campioni non viene emesso. */
		fprintf(csv,
			"%s,%s,%u,%lu,%u,"
			"%s,%u,%u,"
			"%u,%u,%u,%u,%u,%u,"
			"%llu,%u,%llu,"
			"0,0,0\n",
			cfg.run_id, cfg.policy_label,
			cfg.bw_mbit, cfg.obj_bytes, cfg.iteration,
			ip, st->dport, st->sport,
			st->iw_route, st->iw,
			st->cwnd, st->srtt_us, st->min_rtt_us, st->retrans,
			(unsigned long long)st->bytes_acked, st->mss,
			(unsigned long long)((st->t_close_ns - st->t_open_ns) / 1000));
		/* Riga per riga: la campagna dura ore, un'interruzione non deve
		 * costare i dati fermi nel buffer. */
		fflush(csv);
	}
	return 0;
}

int main(int argc, char **argv)
{
    struct augmenter_bpf *skel;
    struct bpf_link *link = NULL;
    struct ring_buffer *rb = NULL;      
    int cgroup_fd = -1;                 
    int err = 0;
 
    parse_args(argc, argv);      
	
	if (cfg.iw == 0) {
        fprintf(stderr,
                "augmenter: serve --iw N (N > 0).\n"
                "  N è la finestra statica alta, in segmenti; tararla con\n"
                "  «testbed.py calibrate».\n");
        return 1;
    }
 
    libbpf_set_print(libbpf_print_fn);
 
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
 
    skel = augmenter_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Apertura o caricamento skeleton fallito\n");
        return 1;
    }
 
    cgroup_fd = open(cfg.cgroup, O_RDONLY);
    if (cgroup_fd < 0) {
        fprintf(stderr, "Apertura fallita %s\n", strerror(errno));
        err = -1;
        goto cleanup;
    }
 
    link = bpf_program__attach_cgroup(skel->progs.augmenter, cgroup_fd);
    if (!link) {
        fprintf(stderr, "attach al cgroup fallito\n");
        err = -1;
        goto cleanup;
    }
 
    iw_fd = bpf_map__fd(skel->maps.iw_map);
    if (iw_fd < 0) {
        fprintf(stderr, "bpf_map__fd fallito\n");
        err = -1;
        goto cleanup;
    }

	if (preload_iw_map()) {
        err = -1;
        goto cleanup;
    }
 
    /* Il consumatore del ring buffer: run_analyzer viene chiamata a ogni
     * connessione chiusa. */
    rb = ring_buffer__new(bpf_map__fd(skel->maps.events),
                          run_analyzer, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "creazione del ring buffer fallita\n");
        err = -1;
        goto cleanup;
    }
 
    if (csv_open()) {
        err = -1;
        goto cleanup;
    }
 
    /* «sola osservazione» va inteso rispetto alla politica, non al
     * programma: la finestra non viene adattata durante l'esecuzione,
     * resta quella passata con --iw e scritta in iw_map a ogni record.
     * È il messaggio comparso nei log della campagna. */
    fprintf(stderr, "augmenter: politica «%s», sola osservazione\n",
            cfg.policy_label);
 
    while (!exiting) {
        int n = ring_buffer__poll(rb, 200 /* ms */);
 
        if (n < 0 && n != -EINTR)
            break;
    }
 
    ring_buffer__consume(rb);
 
 cleanup:
    if (csv)                           
        fclose(csv);
    ring_buffer__free(rb);              
    bpf_link__destroy(link);
    if (cgroup_fd >= 0)
        close(cgroup_fd);
    augmenter_bpf__destroy(skel);
    if(err)
        return 1;
    else
        return 0;
}