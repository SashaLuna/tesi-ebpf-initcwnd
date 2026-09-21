/* augmenter.c - politica «ewma»: media mobile esponenziale della finestra
 * osservata.
 *
 * La finestra iniziale verso una destinazione è la media mobile delle
 * connessioni precedenti verso la stessa destinazione. iw_map non viene
 * precaricata: la prima connessione parte con la finestra della route, perché
 * la politica non ha ancora osservato niente.
 *
 * Esempio:
 *   ./augmenter --iw-min 4 --iw-max 469 --alpha-shift 2 \
 *               --csv server_ewma_bw100_200K_it01.csv --policy-label ewma \
 *               --run-id ewma_bw100_200K_it01 \
 *               --bw-mbit 100 --obj-bytes 204800 --iteration 1
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

	/* opzioni della sola politica */
	unsigned int  iw_min;        /* saturazione inferiore, segmenti */
	unsigned int  iw_max;        /* saturazione superiore, segmenti */
	unsigned int  alpha_shift;   /* alfa della media mobile = 1/2^alpha_shift */
	unsigned long min_bytes;     /* sotto questa soglia il record non fa testo */
} cfg = {
	.cgroup       = "/sys/fs/cgroup",
	.csv_path     = NULL,
	.run_id       = "run",
	.policy_label = "ewma",
	.bw_mbit      = 0,
	.obj_bytes    = 0,
	.iteration    = 0,
	/* Il pavimento è la finestra del kernel: una politica non deve poter
	 * fare peggio dell'astensione. */
	.iw_min       = 10,
	.iw_max       = 100,
	.alpha_shift  = 2,           /* alfa = 1/4 */
	.min_bytes    = 0,           /* 0 = metà di --obj-bytes, vedi sotto */
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
		/* opzioni della sola politica */
		else if (!strcmp(a, "--iw-min")       && has_val) cfg.iw_min = atoi(argv[++i]);
		else if (!strcmp(a, "--iw-max")       && has_val) cfg.iw_max = atoi(argv[++i]);
		else if (!strcmp(a, "--alpha-shift")  && has_val) cfg.alpha_shift = atoi(argv[++i]);
		else if (!strcmp(a, "--min-bytes")    && has_val) cfg.min_bytes = strtoul(argv[++i], NULL, 10);
		else
			fprintf(stderr, "augmenter: opzione ignorata «%s»\n", a);
	}

	if (cfg.iw_min < 1)
		cfg.iw_min = 1;
	if (cfg.iw_max < cfg.iw_min)
		cfg.iw_max = cfg.iw_min;
	/* Oltre 8 l'incremento si annulla per differenze piccole e la stima
	 * resterebbe ferma sul primo campione. */
	if (cfg.alpha_shift > 8)
		cfg.alpha_shift = 8;
	if (cfg.min_bytes == 0)
		cfg.min_bytes = cfg.obj_bytes ? cfg.obj_bytes / 2 : 4096;
}

/* Tabella per destinazione. Ricerca lineare su 256 voci: nel banco le
 * destinazioni sono tre, una tabella hash sarebbe complessità inutile. */
#define MAX_DSTS 256

struct dst_state {
	__u32 dst_ip;      /* chiave, ordine di host; 0 = voce libera */
	__u32 samples;     /* campioni ENTRATI nella stima */
	__u32 scartati;    /* record visti ma non entrati nella stima */
	__u32 ewma_fx;     /* la stima, in virgola fissa */
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

static int iw_fd = -1;

/* --- la politica --- */

/* Stima in virgola fissa (valore reale per 256): l'aggiornamento è una
 * sottrazione, uno scorrimento e una somma. */
#define FRAC_BITS 8

static unsigned int clamp_iw(unsigned int v)
{
	if (v < cfg.iw_min) return cfg.iw_min;
	if (v > cfg.iw_max) return cfg.iw_max;
	return v;
}

/* Arrotondamento al più vicino: troncare introdurrebbe mezzo segmento
 * di distorsione a ogni lettura. */
static unsigned int stima(const struct dst_state *d)
{
	return (d->ewma_fx + (1u << (FRAC_BITS - 1))) >> FRAC_BITS;
}

/* Il campione da cui si impara: il minimo fra la cwnd massima e i segmenti
 * davvero riscontrati. La sola cwnd massima innescherebbe una retroazione
 * positiva, perché cresce anche quando a finire è l'oggetto e non a
 * saturare il percorso. Il ragionamento esteso è nel capitolo 5. */
static unsigned int campione_da(const struct aug_stats *st)
{
	unsigned int segmenti;

	if (!st->mss)                 /* non dovrebbe accadere: prudenza */
		return st->cwnd;

	/* Per eccesso: con la divisione intera l'ultimo segmento aspetterebbe un
	 * riscontro e la connessione pagherebbe un RTT in più. */
	segmenti = (unsigned int)((st->bytes_acked + st->mss - 1) / st->mss);
	if (segmenti && segmenti < st->cwnd)
		return segmenti;
	return st->cwnd;
}

static void ewma_update(struct dst_state *d, __u32 sample)
{
	__u32 s = sample << FRAC_BITS;

	if (d->samples == 0) {
		/* Primo campione: si inizializza la stima; partire da zero
		 * misurerebbe il transitorio invece del regime. */
		d->ewma_fx = s;
	} else {
		/* ewma += alfa * (campione - ewma), alfa = 1/2^alpha_shift.
		 * Con segno: il campione può essere minore della stima. */
		d->ewma_fx = (__u32)((long)d->ewma_fx +
			     (((long)s - (long)d->ewma_fx) >> cfg.alpha_shift));
	}
	d->samples++;
}

/* Restituisce la finestra da scrivere in iw_map, oppure 0 se da questo
 * record non c'è niente da imparare. I trasferimenti troppo corti (per
 * esempio la richiesta di probe.bin) non misurano la capacità del
 * percorso e sarebbero il primo campione di quella destinazione: si
 * scartano, ma finiscono comunque nel CSV. */
static unsigned int politica(struct dst_state *d, const struct aug_stats *st)
{
	if (st->bytes_acked < cfg.min_bytes) {
		d->scartati++;
		return 0;
	}
	ewma_update(d, campione_da(st));
	return clamp_iw(stima(d));
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
	unsigned int iw;

	(void)ctx;
	if (len < sizeof(*st))
		return 0;

	d = dst_lookup(st->dst_ip);
	if (!d) {
		fprintf(stderr, "augmenter: tabella delle destinazioni piena\n");
		return 0;
	}

	iw = politica(d, st);

	if (iw) {
		__u32 key = st->dst_ip, val = iw;

		if (bpf_map_update_elem(iw_fd, &key, &val, BPF_ANY) == 0)
			d->iw_current = val;
		else
			fprintf(stderr, "scrittura in iw_map fallita: %s\n",
				strerror(errno));
	}

	a.s_addr = htonl(st->dst_ip);
	inet_ntop(AF_INET, &a, ip, sizeof(ip));

	printf("analyzer: dst=%s IW %u->%u max_cwnd=%u campione=%u "
	       "srtt=%.2f ms retrans=%u  =>  stima=%u%s\n",
	       ip, st->iw_route, st->iw, st->cwnd, campione_da(st),
	       st->srtt_us / 1000.0, st->retrans,
	       iw ? iw : d->iw_current,
	       iw ? "" : "  (record scartato: troppo corto)");

	if (csv) {
		fprintf(csv,
			"%s,%s,%u,%lu,%u,"
			"%s,%u,%u,"
			"%u,%u,%u,%u,%u,%u,"
			"%llu,%u,%llu,"
			"%u,%u,0\n",
			cfg.run_id, cfg.policy_label,
			cfg.bw_mbit, cfg.obj_bytes, cfg.iteration,
			ip, st->dport, st->sport,
			/* Sulla prima riga di ogni destinazione iw_route e iw_applied
			 * coincidono: la politica non ha ancora osservato niente. */
			st->iw_route, st->iw,
			st->cwnd, st->srtt_us, st->min_rtt_us, st->retrans,
			(unsigned long long)st->bytes_acked, st->mss,
			(unsigned long long)((st->t_close_ns - st->t_open_ns) / 1000),
			/* ewma_after: la stima dopo questo record, cioè la finestra che
			 * userà la prossima connessione verso questa destinazione.
			 * samples conta i campioni entrati nella stima, non i record
			 * visti. penalties esiste solo nella politica loss-aware. */
			stima(d), d->samples);
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
	int i;

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

	fprintf(stderr,
		"augmenter: politica «%s» — media mobile con alfa=1/%u, "
		"finestra saturata in [%u,%u], campioni sotto %lu byte scartati\n",
		cfg.policy_label, 1u << cfg.alpha_shift,
		cfg.iw_min, cfg.iw_max, cfg.min_bytes);

	while (!exiting) {
		int n = ring_buffer__poll(rb, 200 /* ms */);

		if (n < 0 && n != -EINTR)
			break;
	}

	/* Ultimo giro senza attesa: raccoglie le ultime connessioni della cella. */
	ring_buffer__consume(rb);

	/* Riepilogo: mostra se la stima è arrivata a regime o si è fermata
	 * contro una saturazione. */
	fprintf(stderr, "augmenter: stima finale per destinazione\n");
	for (i = 0; i < MAX_DSTS; i++) {
		struct in_addr a;
		char ip[INET_ADDRSTRLEN];

		if (!dsts[i].dst_ip)
			continue;
		a.s_addr = htonl(dsts[i].dst_ip);
		inet_ntop(AF_INET, &a, ip, sizeof(ip));
		fprintf(stderr, "    %-15s stima=%-5u campioni=%-4u scartati=%u%s\n",
			ip, stima(&dsts[i]), dsts[i].samples, dsts[i].scartati,
			stima(&dsts[i]) >= cfg.iw_max ? "   <- contro la saturazione superiore" : "");
	}

 cleanup:
	if (csv)
		fclose(csv);
	ring_buffer__free(rb);
	bpf_link__destroy(link);
	if (cgroup_fd >= 0)
		close(cgroup_fd);
	augmenter_bpf__destroy(skel);
	if (err)
		return 1;
	else
		return 0;
}
