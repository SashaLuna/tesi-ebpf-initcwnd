#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
stats.py — aggregazione dei CSV della campagna.

    python3 analysis/stats.py results/ [--out analisi/] [--latex]

Che cosa fa
-----------
1. Congiunge le righe lato client e lato server. La chiave è la coppia
   (indirizzo del client, porta effimera del client): una connessione TCP è
   identificata dalla quaterna, e nella nostra topologia indirizzo e porta del
   server sono costanti, quindi due elementi bastano. Il risultato è
   `connessioni.csv`: una riga per connessione con le metriche di entrambi i
   lati, che è il documento grezzo da cui discende tutto il resto.

2. Calcola per ogni cella (politica, banda, taglia, client) media, mediana,
   deviazione standard campionaria e novantacinquesimo percentile di:
   FCT, goodput, tempo del solo trasferimento, ritrasmissioni, RTT di
   trasporto, finestra iniziale applicata, cwnd massima; più la quota di
   flussi con almeno una ritrasmissione. Esce in `riepilogo.csv`.

   **Il FCT è misurato dal SYN all'ultimo byte**, apertura della connessione
   compresa: è la convenzione della letteratura sul traffico di datacenter. La
   costante `FCT_DEF` in cima al file è l'unico posto in cui la scelta è
   scritta, e cambiarla ricalcola FCT e goodput ovunque, tabelle comprese.
   Il tempo del solo trasferimento resta riportato accanto, così la differenza
   fra i due — cioè il costo dell'apertura — è sempre leggibile.

   Le stesse celle portano anche le colonne `*_median_iter_mean` e
   `*_median_iter_std`: la mediana calcolata DENTRO ciascuna iterazione, e poi
   media e dispersione di quelle dieci mediane. È la lettura fedele di «dieci
   iterazioni per tener conto della variabilità dello stato del sistema»,
   perché isola la variabilità fra ripetizioni da quella fra i giri di una
   stessa ripetizione. `riepilogo_per_iterazione.csv` riporta il dettaglio.

3. Scrive `connessioni_itNN.csv`, un file per ciascuna delle dieci iterazioni,
   nella forma chiesta dal protocollo. I file per cella restano dove sono:
   questi sono una vista, non una sostituzione.

4. Con --latex, scrive tabelle booktabs pronte da includere nella tesi.

Nessuna dipendenza oltre la libreria standard.
"""

import argparse
import csv
import math
import os
import re
import statistics
import sys
from collections import defaultdict


# ===========================================================================
# Statistica descrittiva
# ===========================================================================

def percentile(xs, q):
    """Percentile con interpolazione lineare fra i due ranghi adiacenti, la
    stessa convenzione di numpy.percentile e di R con type=7. Dichiararla
    conta: con dieci iterazioni da quindici giri il p95 cade fra due campioni
    e convenzioni diverse danno numeri diversi."""
    if not xs:
        return float("nan")
    s = sorted(xs)
    if len(s) == 1:
        return float(s[0])
    k = (len(s) - 1) * q
    lo, hi = math.floor(k), math.ceil(k)
    if lo == hi:
        return float(s[int(k)])
    return s[lo] * (hi - k) + s[hi] * (k - lo)


def describe(xs):
    """media, mediana, deviazione standard campionaria, p95, numero."""
    xs = [x for x in xs if x is not None and not math.isnan(x)]
    if not xs:
        return dict(mean=float("nan"), median=float("nan"),
                    std=float("nan"), p95=float("nan"), n=0)
    return dict(
        mean=statistics.fmean(xs),
        median=statistics.median(xs),
        std=statistics.stdev(xs) if len(xs) > 1 else 0.0,
        p95=percentile(xs, 0.95),
        n=len(xs),
    )


# ===========================================================================
# Lettura e giunzione
# ===========================================================================

RUN_RE = re.compile(r"^(?P<policy>[a-z0-9]+)_bw(?P<bw>\d+)_"
                    r"(?P<obj>[0-9]+[KM])_it(?P<it>\d+)$")


# ---------------------------------------------------------------------------
# LA DEFINIZIONE DEL FCT — è una scelta, e sta scritta in un posto solo.
#
#   "B"  dal SYN all'ultimo byte, cioè il flusso intero, apertura compresa.
#        È la convenzione della letteratura sul traffico di datacenter, ed è
#        anche il tempo che l'utente percepisce. SCELTA ADOTTATA.
#
#   "A"  dalla fine dell'apertura all'ultimo byte, cioè il solo trasferimento.
#        Esclude un RTT identico in tutte le politiche, e quindi non lo diluisce
#        nel confronto.
#
# Non è una sfumatura: su un oggetto da 1 KB le due misure stanno in rapporto
# 2 a 1, e sul beneficio dichiarato ballano una dozzina di punti percentuali.
# Cambiare questa costante ricalcola FCT *e goodput* ovunque, tabelle LaTeX
# comprese; le due grandezze grezze restano entrambe in connessioni.csv, quindi
# l'inversione non richiede di rifare le misure.
# ---------------------------------------------------------------------------
FCT_DEF = "B"

FCT_DESCRIZIONE = {
    "B": "dal SYN all'ultimo byte",
    "A": "dalla fine dell'apertura all'ultimo byte",
}[FCT_DEF]


def read_csv(path):
    with open(path, newline="") as f:
        return list(csv.DictReader(f))


def collect(results_dir):
    """Restituisce (righe congiunte, diagnostica)."""
    client_files, server_files = {}, {}
    for root, _dirs, files in os.walk(results_dir):
        for fn in files:
            if not fn.endswith(".csv"):
                continue
            if fn.startswith("client_"):
                client_files[fn[len("client_"):-4]] = os.path.join(root, fn)
            elif fn.startswith("server_"):
                server_files[fn[len("server_"):-4]] = os.path.join(root, fn)

    diag = dict(cells=0, only_client=[], only_server=[], rows_client=0,
                rows_server=0, joined=0, http_errors=0, unmatched=0)
    diag["only_client"] = sorted(set(client_files) - set(server_files))
    diag["only_server"] = sorted(set(server_files) - set(client_files))

    joined = []
    for run_id in sorted(set(client_files) & set(server_files)):
        diag["cells"] += 1
        crows = read_csv(client_files[run_id])
        srows = read_csv(server_files[run_id])
        diag["rows_client"] += len(crows)
        diag["rows_server"] += len(srows)

        # Indice lato server: (ip del client, porta del client) -> riga.
        # Se la stessa coppia ricorre — porta effimera riusata nella stessa
        # cella — si tiene l'ultima, che è quella cronologicamente coerente
        # con la richiesta più recente.
        sidx = {}
        for r in srows:
            sidx[(r["dst_ip"], r["dport"])] = r

        for c in crows:
            if c["http_code"] != "200":
                diag["http_errors"] += 1
                continue
            s = sidx.get((c["client_ip"], c["local_port"]))
            if s is None:
                diag["unmatched"] += 1
                continue
            joined.append(merge(c, s))
            diag["joined"] += 1
    return joined, diag


def merge(c, s):
    """Una riga per connessione. I nomi delle colonne restano quelli dei due
    CSV di origine, con prefisso solo dove collidono."""

    # I tre istanti che curl riporta, e le due durate che se ne ricavano.
    t_conn = float(c["time_connect_s"])
    t_total = float(c["time_total_s"])
    trasferimento_s = max(t_total - t_conn, 1e-9)
    fct_s = t_total if FCT_DEF == "B" else trasferimento_s

    # Il goodput si ricalcola QUI e non si legge dal CSV del client: quella
    # colonna è stata scritta dividendo per il solo trasferimento, e con la
    # definizione B darebbe un valore incoerente con il FCT riportato accanto.
    # La divisione dev'essere per la stessa durata che si chiama FCT.
    scaricati = int(c["size_download"])
    goodput = scaricati * 8.0 / fct_s / 1e6

    return dict(
        run_id=c["run_id"],
        policy=c["policy"],
        bw_mbit=int(c["bw_mbit"]),
        obj_label=c["obj_label"],
        obj_bytes=int(c["obj_bytes"]),
        iteration=int(c["iteration"]),
        client=c["client"],
        client_ip=c["client_ip"],
        rtt_nominal_ms=float(c["rtt_nominal_ms"]),
        round=int(c["round"]),
        port=int(c["local_port"]),
        # --- lato client ---
        size_download=scaricati,
        time_connect_ms=t_conn * 1000.0,
        time_ttfb_ms=float(c["time_starttransfer_s"]) * 1000.0,
        time_total_ms=t_total * 1000.0,
        # fct_ms è la definizione ADOTTATA; trasferimento_ms è sempre il solo
        # trasferimento. Averle entrambe nel documento grezzo significa che
        # l'altra lettura si ottiene senza rifare una sola misura.
        fct_ms=fct_s * 1000.0,
        trasferimento_ms=trasferimento_s * 1000.0,
        goodput_mbps=goodput,
        # --- lato server ---
        iw_route=int(s["iw_route"]),
        iw_applied=int(s["iw_applied"]),
        max_cwnd=int(s["max_cwnd"]),
        srtt_ms=int(s["srtt_us"]) / 1000.0,
        min_rtt_ms=int(s["min_rtt_us"]) / 1000.0,
        retrans=int(s["retrans"]),
        bytes_acked=int(s["bytes_acked"]),
        mss=int(s["mss"]),
        duration_ms=int(s["duration_us"]) / 1000.0,
        ewma_after=int(s["ewma_after"]),
        samples=int(s["samples"]),
        penalties=int(s["penalties"]),
    )


# ===========================================================================
# Riepilogo
# ===========================================================================

METRICS = [
    ("fct_ms",           "FCT [ms] (%s)" % FCT_DESCRIZIONE),
    ("goodput_mbps",     "goodput [Mbit/s]"),
    # Il solo trasferimento, riportato accanto al FCT: la differenza fra i due
    # è l'apertura della connessione, ed è la grandezza che mostra quanta parte
    # del guadagno venga dalla finestra iniziale e quanta sia costo fisso.
    ("trasferimento_ms", "tempo di trasferimento [ms]"),
    ("retrans",          "ritrasmissioni"),
    ("srtt_ms",          "RTT di trasporto [ms]"),
    ("iw_applied",       "IW applicata [seg]"),
    ("max_cwnd",         "cwnd massima [seg]"),
]


def summarize(rows, by_client=True, by_iteration=False):
    key_fields = ["policy", "bw_mbit", "obj_label"] + \
                 (["client"] if by_client else []) + \
                 (["iteration"] if by_iteration else [])
    groups = defaultdict(list)
    for r in rows:
        groups[tuple(r[k] for k in key_fields)].append(r)

    out = []
    for key in sorted(groups, key=lambda k: (k[1], str(k[2]), str(k[0]),
                                             k[3] if len(k) > 3 else "")):
        g = groups[key]
        rec = dict(zip(key_fields, key))
        rec["obj_bytes"] = g[0]["obj_bytes"]
        rec["rtt_nominal_ms"] = g[0]["rtt_nominal_ms"] if by_client else ""
        rec["n_conn"] = len(g)
        rec["n_iterations"] = len(set(r["iteration"] for r in g))
        for field, _label in METRICS:
            d = describe([r[field] for r in g])
            for stat in ("mean", "median", "std", "p95"):
                rec["%s_%s" % (field, stat)] = round(d[stat], 4)
        # Quota di flussi con almeno una ritrasmissione: è la grandezza che il
        # protocollo chiede esplicitamente accanto alle statistiche del
        # contatore, perché media e mediana delle ritrasmissioni possono
        # essere entrambe nulle mentre una coda di flussi soffre.
        rec["retrans_flow_pct"] = round(
            100.0 * sum(1 for r in g if r["retrans"] > 0) / len(g), 3)
        rec["penalties_total"] = sum(r["penalties"] for r in g)
        out.append(rec)
    return out


def statistiche_fra_iterazioni(rows, per_client):
    """Aggiunge a ogni cella la dispersione FRA le dieci iterazioni.

    Perché serve. Le dieci ripetizioni sono state chieste «per tener conto
    della variabilità dello stato del sistema». Ma la deviazione standard
    calcolata su tutte le connessioni messe insieme mescola due variabilità
    diverse: quella fra i quindici giri dentro una stessa iterazione, e quella
    fra un'iterazione e la successiva — che è proprio quella che le ripetizioni
    dovevano isolare, e l'unica che dica qualcosa sulla stabilità della
    macchina.

    Qui si calcola la MEDIANA dentro ciascuna iterazione, e poi media e
    deviazione standard di quelle dieci mediane. La dispersione che ne esce è
    fra le ripetizioni, ed è anche la base per una barra d'errore legittima
    sulla mediana nei grafici.

    Le colonne del riepilogo per connessione restano dove sono: le due letture
    convivono, e si sceglie in fase di scrittura quale riportare.
    """
    per_iter = defaultdict(lambda: defaultdict(list))
    for r in rows:
        k = (r["policy"], r["bw_mbit"], r["obj_label"], r["client"])
        per_iter[k][r["iteration"]].append(r)

    for rec in per_client:
        k = (rec["policy"], rec["bw_mbit"], rec["obj_label"], rec["client"])
        gruppi = [g for g in per_iter.get(k, {}).values() if g]
        for field, _label in METRICS:
            mediane = [statistics.median([r[field] for r in g]) for g in gruppi]
            d = describe(mediane)
            rec["%s_median_iter_mean" % field] = round(d["mean"], 4)
            rec["%s_median_iter_std" % field] = round(d["std"], 4)
        # Anche la quota di flussi con ritrasmissioni ha senso per iterazione:
        # è una proporzione, e la sua variabilità fra ripetizioni dice se le
        # perdite siano un fenomeno stabile o un accidente di una corsa.
        quote = [100.0 * sum(1 for r in g if r["retrans"] > 0) / len(g)
                 for g in gruppi]
        d = describe(quote)
        rec["retrans_flow_pct_iter_mean"] = round(d["mean"], 3)
        rec["retrans_flow_pct_iter_std"] = round(d["std"], 3)
    return per_client


def scrivi_per_iterazione(rows, outdir):
    """Un file per iterazione, con dentro tutte le connessioni di quella
    ripetizione: è la forma che il protocollo chiede esplicitamente. I file per
    cella restano dove sono — questi sono una vista, non una sostituzione."""
    per_it = defaultdict(list)
    for r in rows:
        per_it[r["iteration"]].append(r)
    scritti = []
    for it in sorted(per_it):
        p = os.path.join(outdir, "connessioni_it%02d.csv" % it)
        write_csv(p, per_it[it])
        scritti.append((p, len(per_it[it])))
    return scritti


# ===========================================================================
# Tabelle LaTeX
# ===========================================================================

def tex_escape(s):
    return str(s).replace("_", r"\_").replace("%", r"\%")


POLICY_LABEL = {
    "static10":   r"IW = 10",
    "metrics":    r"tcp\_metrics",
    "statichigh": r"IW statica alta",
    "statichigh-bpf": r"IW statica alta (eBPF)",
    "ewma":       r"eBPF EWMA",
    "lossaware":  r"eBPF loss-aware",
    "lossaware-disc": r"eBPF loss-aware (discr.)",
}


def latex_table(summary, bw, field, stat, caption, label, fmt="%.1f"):
    """Righe = (taglia, client); colonne = politiche."""
    policies = sorted({r["policy"] for r in summary},
                      key=lambda p: list(POLICY_LABEL).index(p)
                      if p in POLICY_LABEL else 99)
    rows = defaultdict(dict)
    order = []
    for r in summary:
        if r["bw_mbit"] != bw:
            continue
        k = (r["obj_bytes"], r["obj_label"], r["client"])
        if k not in rows:
            order.append(k)
        rows[k][r["policy"]] = r.get("%s_%s" % (field, stat))

    order.sort()
    lines = [
        r"\begin{table}[htbp]",
        r"  \centering",
        r"  \caption{%s}" % caption,
        r"  \label{%s}" % label,
        r"  \begin{tabular}{ll%s}" % ("r" * len(policies)),
        r"    \toprule",
        r"    Oggetto & Client & %s \\" %
        " & ".join(POLICY_LABEL.get(p, tex_escape(p)) for p in policies),
        r"    \midrule",
    ]
    last_obj = None
    for (_b, obj, client) in order:
        cells = []
        for p in policies:
            v = rows[(_b, obj, client)].get(p)
            cells.append("---" if v is None or (isinstance(v, float)
                         and math.isnan(v)) else fmt % v)
        shown = obj if obj != last_obj else ""
        if obj != last_obj and last_obj is not None:
            lines.append(r"    \addlinespace")
        last_obj = obj
        lines.append("    %s & %s & %s \\\\" % (shown, client, " & ".join(cells)))
    lines += [r"    \bottomrule", r"  \end{tabular}", r"\end{table}", ""]
    return "\n".join(lines)


# ===========================================================================
# main
# ===========================================================================

def write_csv(path, rows, fieldnames=None):
    if not rows:
        return
    fieldnames = fieldnames or list(rows[0].keys())
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(rows)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("results", help="cartella dei risultati della campagna")
    ap.add_argument("--out", default=None,
                    help="cartella di uscita (default: <results>/analisi)")
    ap.add_argument("--latex", action="store_true",
                    help="genera anche le tabelle booktabs")
    args = ap.parse_args()

    outdir = args.out or os.path.join(args.results, "analisi")
    os.makedirs(outdir, exist_ok=True)

    rows, diag = collect(args.results)
    if not rows:
        sys.exit("Nessuna connessione ricostruita: controllare che in %s ci "
                 "siano coppie client_*.csv / server_*.csv." % args.results)

    print("Celle elaborate          : %d" % diag["cells"])
    print("Righe lato client        : %d" % diag["rows_client"])
    print("Righe lato server        : %d" % diag["rows_server"])
    print("Connessioni ricostruite  : %d" % diag["joined"])
    if diag["http_errors"]:
        print("  richieste non riuscite : %d  (escluse)" % diag["http_errors"])
    if diag["unmatched"]:
        pct = 100.0 * diag["unmatched"] / max(1, diag["rows_client"])
        print("  senza riscontro server : %d  (%.2f %%)"
              % (diag["unmatched"], pct))
        if pct > 2:
            print("  ATTENZIONE: quota alta. Di solito significa che il "
                  "caricatore è stato fermato prima che i socket si "
                  "chiudessero, oppure che il programma non era agganciato "
                  "al cgroup di nginx.")
    for name in diag["only_client"]:
        print("  manca il CSV server per %s" % name)
    for name in diag["only_server"]:
        print("  manca il CSV client per %s" % name)
    print()

    p_conn = os.path.join(outdir, "connessioni.csv")
    write_csv(p_conn, rows)
    print("scritto %s  (%d righe)" % (p_conn, len(rows)))

    for p, n in scrivi_per_iterazione(rows, outdir):
        print("scritto %s  (%d righe)" % (p, n))

    per_client = summarize(rows, by_client=True)
    statistiche_fra_iterazioni(rows, per_client)
    p_sum = os.path.join(outdir, "riepilogo.csv")
    write_csv(p_sum, per_client)
    print("scritto %s  (%d celle)" % (p_sum, len(per_client)))

    per_iter = summarize(rows, by_client=True, by_iteration=True)
    p_it = os.path.join(outdir, "riepilogo_per_iterazione.csv")
    write_csv(p_it, per_iter)
    print("scritto %s  (%d celle × iterazione)" % (p_it, len(per_iter)))

    aggregate = summarize(rows, by_client=False)
    p_agg = os.path.join(outdir, "riepilogo_aggregato.csv")
    write_csv(p_agg, aggregate)
    print("scritto %s  (%d celle)" % (p_agg, len(aggregate)))

    # --- confronto a colpo d'occhio sul terminale ---
    print("\nFCT mediano [ms] — %s — ± dev. std. fra le iterazioni\n"
          % FCT_DESCRIZIONE)
    policies = sorted({r["policy"] for r in per_client},
                      key=lambda p: list(POLICY_LABEL).index(p)
                      if p in POLICY_LABEL else 99)
    W = 20
    hdr = "%-6s %-6s %-5s" % ("banda", "ogg", "cl")
    print(hdr + "".join("%*s" % (W, p) for p in policies))
    print("-" * (len(hdr) + W * len(policies)))
    seen = {}
    for r in per_client:
        seen.setdefault((r["bw_mbit"], r["obj_bytes"], r["obj_label"],
                         r["client"]), {})[r["policy"]] = (
            r["fct_ms_median"], r.get("fct_ms_median_iter_std"))
    for k in sorted(seen):
        bw, _b, obj, cl = k
        line = "%-6d %-6s %-5s" % (bw, obj, cl)
        base = (seen[k].get("static10") or (None, None))[0]
        for p in policies:
            v, sd = seen[k].get(p, (None, None))
            if v is None or math.isnan(v):
                line += "%*s" % (W, "---")
                continue
            testo = "%.1f" % v
            if sd is not None and not math.isnan(sd):
                testo += "±%.1f" % sd
            if base and p != "static10" and not math.isnan(base) and base > 0:
                testo += " (%+.0f%%)" % (100.0 * (v - base) / base)
            line += "%*s" % (W, testo)
        print(line)

    # --- tabelle ---
    if args.latex:
        texdir = os.path.join(outdir, "tabelle")
        os.makedirs(texdir, exist_ok=True)
        bws = sorted({r["bw_mbit"] for r in per_client})
        for bw in bws:
            specs = [
                ("fct_ms", "median", "%.1f",
                 "Tempo di completamento del flusso (FCT) mediano, in ms, "
                 "misurato %s; collo di bottiglia a %d Mbit/s."
                 % (FCT_DESCRIZIONE, bw),
                 "tab:fct-med-%d" % bw, "fct_mediano"),
                ("fct_ms", "p95", "%.1f",
                 "Novantacinquesimo percentile del FCT, in ms, misurato %s; "
                 "collo di bottiglia a %d Mbit/s." % (FCT_DESCRIZIONE, bw),
                 "tab:fct-p95-%d" % bw, "fct_p95"),
                ("trasferimento_ms", "median", "%.1f",
                 "Tempo del solo trasferimento (FCT al netto dell'apertura "
                 "della connessione) mediano, in ms; collo di bottiglia a "
                 "%d Mbit/s." % bw,
                 "tab:trasf-med-%d" % bw, "trasferimento_mediano"),
                ("goodput_mbps", "mean", "%.2f",
                 "Goodput medio (Mbit/s), calcolato sul FCT misurato %s; "
                 "collo di bottiglia a %d Mbit/s." % (FCT_DESCRIZIONE, bw),
                 "tab:goodput-%d" % bw, "goodput_medio"),
                ("iw_applied", "mean", "%.1f",
                 "Finestra iniziale media effettivamente applicata "
                 "(segmenti), collo di bottiglia a %d Mbit/s." % bw,
                 "tab:iw-%d" % bw, "iw_media"),
                ("max_cwnd", "mean", "%.1f",
                 "Finestra di congestione massima media (segmenti), collo di "
                 "bottiglia a %d Mbit/s." % bw, "tab:cwnd-%d" % bw,
                 "cwnd_massima"),
                ("retrans", "mean", "%.2f",
                 "Ritrasmissioni medie per connessione, collo di bottiglia a "
                 "%d Mbit/s." % bw, "tab:retrans-%d" % bw, "retrans_medie"),
            ]
            for field, stat, fmt, cap, lab, fname in specs:
                tex = latex_table(per_client, bw, field, stat, cap, lab, fmt)
                path = os.path.join(texdir, "%s_bw%d.tex" % (fname, bw))
                with open(path, "w") as f:
                    f.write(tex)

            # quota di flussi con ritrasmissioni: colonna già percentuale,
            # quindi non passa da describe()
            fake = [dict(r, retransflow_median=r["retrans_flow_pct"])
                    for r in per_client]
            tex = latex_table(
                fake, bw, "retransflow", "median",
                "Quota di flussi con almeno una ritrasmissione (\\%%), collo "
                "di bottiglia a %d Mbit/s." % bw,
                "tab:retransflow-%d" % bw, "%.1f")
            with open(os.path.join(texdir,
                      "retrans_quota_bw%d.tex" % bw), "w") as f:
                f.write(tex)
        print("\nscritte le tabelle in %s" % texdir)
        print("Nel preambolo serve \\usepackage{booktabs}.")


if __name__ == "__main__":
    main()
