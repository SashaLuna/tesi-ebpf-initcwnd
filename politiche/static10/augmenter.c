/* augmenter.c - politica «static10»: nessun intervento.
 *
 * Il caricatore non scrive mai in iw_map: le connessioni partono con la
 * finestra iniziale della route. È il riferimento con cui si confrontano le
 * altre politiche, e raccoglie le stesse colonne di CSV.
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
} cfg = {
	.cgroup       = "/sys/fs/cgroup",
	.csv_path     = NULL,
	.run_id       = "run",
	.policy_label = "static10",
	.bw_mbit      = 0,
	.obj_bytes    = 0,
	.iteration    = 0,
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
		else
			fprintf(stderr, "augmenter: opzione ignorata «%s»\n", a);
	}
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
	return vfprintf(stderr, format, args);
}

static volatile sig_atomic_t exiting = 0;

static void sig_handler(int sig)
{
	exiting = 1;
}

static int run_analyzer(void *ctx, void *data, size_t len)
{
	struct aug_stats *st = data;
    struct in_addr a;

	if (len < sizeof(*st))
		return 0;
 
	a.s_addr = htonl(st->dst_ip);
	printf("analyzer: dst=%s cwnd=%u srtt=%.2f ms retrans=%u -> IW=%u\n",
	       inet_ntoa(a), st->cwnd, st->srtt_us / 1000.0,
	       st->retrans, st->iw);
 
	if (csv) {
		a.s_addr = htonl(st->dst_ip);
		fprintf(csv,
			"%s,%s,%u,%lu,%u,"
			"%s,%u,%u,"
			"%u,%u,%u,%u,%u,%u,"
			"%llu,%u,%llu,"
			"0,0,0\n",
			cfg.run_id, cfg.policy_label,
			cfg.bw_mbit, cfg.obj_bytes, cfg.iteration,
			inet_ntoa(a), st->dport, st->sport,
		
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
    int iw_fd = -1;
    int err = 0;
 
    parse_args(argc, argv);             
 
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