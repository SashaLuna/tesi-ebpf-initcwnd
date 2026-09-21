#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
conformita.py — verifica meccanica che i dati prodotti rispettino il protocollo.

    python3 analysis/conformita.py results/
    python3 analysis/conformita.py results/ --completo

Non guarda il codice: guarda i CSV che il codice ha prodotto. È la differenza
fra «il programma dovrebbe fare X» e «i dati dimostrano che X è successo», e
solo la seconda vale come prova.

Quattro blocchi di controlli:

  COPERTURA      quali politiche, bande, taglie, iterazioni e client ci sono,
                 rispetto alla griglia del protocollo. Informativo per
                 costruzione — una prova parziale è legittima — a meno di
                 --completo, che pretende la griglia intera.

  RACCOLTA       che ogni cella sia completa e che i due lati si congiungano.
                 Qui un fallimento è un fallimento anche su dati parziali.

  PLAUSIBILITÀ   che i valori letti dal kernel abbiano senso. Intercetta il
                 guasto peggiore: struct disallineate fra kernel e spazio
                 utente, che producono numeri plausibili e sbagliati.

  POLITICHE      che ogni politica faccia quello che dichiara: la 1 non deve
                 mai intervenire, le altre devono.

Esce con stato diverso da zero se un controllo dei blocchi 2-4 fallisce.
"""

import argparse
import os
import sys
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import stats  # noqa: E402   la giunzione è una sola, e sta lì


# ===========================================================================
# La griglia che il protocollo prescrive
# ===========================================================================

POLITICHE = ["static10", "metrics", "statichigh", "ewma", "lossaware",
             "lossaware-disc"]
# «statichigh-bpf» sta fuori dalla griglia principale: è la misura del
# costo del percorso eBPF, non una sesta configurazione a confronto.
# Non entra nella copertura, ma se compare nei dati viene controllata
# come politica attiva — perché deve intervenire sulla finestra.
# Le tre bande della griglia. Sorgente di verità: BANDWIDTHS in testbed.py —
# qui sono ripetute per non trascinare la dipendenza da Mininet dentro
# l'analisi, che gira senza privilegi e su una macchina qualsiasi. Se là
# cambiano, vanno cambiate anche qui: è l'unica duplicazione del progetto, ed
# è deliberata.
BANDE = [20, 50, 100]
TAGLIE = ["1K", "10K", "30K", "200K", "1M", "10M"]
ITERAZIONI = 10
CLIENT = ["h2", "h3", "h4"]
GIRI_MINIMI = 10          # «almeno 10 o 15 volte»

# Configurazioni che per definizione NON devono toccare la finestra: la
# decisione, se c'è, passa dalla route e non da eBPF.
PASSIVE = {"static10", "metrics", "statichigh"}

MSS_ATTESO = (1400, 1500)   # MTU 1500 meno le intestazioni


# ===========================================================================
# Presentazione
# ===========================================================================

BOLD, GRN, YLW, RED, OFF = ("\033[1m", "\033[32m", "\033[33m",
                            "\033[31m", "\033[0m")


class Esito:
    def __init__(self):
        self.falliti = 0
        self.passati = 0

    def titolo(self, testo):
        print("\n%s==>%s %s" % (BOLD, OFF, testo))

    def ok(self, nome, dettaglio=""):
        self.passati += 1
        print("    %s[ok]%s  %-52s %s" % (GRN, OFF, nome, dettaglio))

    def ko(self, nome, dettaglio="", righe=()):
        self.falliti += 1
        print("    %s[KO]%s  %-52s %s" % (RED, OFF, nome, dettaglio))
        for r in list(righe)[:6]:
            print("          %s" % r)
        if len(list(righe)) > 6:
            print("          … e altre %d" % (len(list(righe)) - 6))

    def info(self, nome, dettaglio=""):
        print("    %-58s %s" % (nome, dettaglio))

    def att(self, nome, dettaglio=""):
        print("    %s[att]%s %-52s %s" % (YLW, OFF, nome, dettaglio))


# ===========================================================================
# Copertura
# ===========================================================================

def copertura(e, righe, completo):
    e.titolo("Copertura della griglia")

    def confronta(nome, presenti, attesi):
        presenti = sorted(set(presenti), key=lambda x: (attesi.index(x)
                          if x in attesi else 99, str(x)))
        mancanti = [a for a in attesi if a not in presenti]
        extra = [p for p in presenti if p not in attesi]
        testo = "%d/%d" % (len(presenti) - len(extra), len(attesi))
        det = "presenti: %s" % ", ".join(str(p) for p in presenti)
        if mancanti:
            det += "   mancano: %s" % ", ".join(str(m) for m in mancanti)
        if extra:
            det += "   in più: %s" % ", ".join(str(x) for x in extra)
        if mancanti and completo:
            e.ko("%s %s" % (nome, testo), det)
        else:
            e.info("%s %s" % (nome, testo), det)

    confronta("politiche ", [r["policy"] for r in righe], POLITICHE)
    confronta("bande     ", [r["bw_mbit"] for r in righe], BANDE)
    confronta("taglie    ", [r["obj_label"] for r in righe], TAGLIE)
    confronta("client    ", [r["client"] for r in righe], CLIENT)

    iters = sorted({r["iteration"] for r in righe})
    testo = "%d/%d" % (len(iters), ITERAZIONI)
    det = "presenti: %s" % ", ".join(str(i) for i in iters)
    if len(iters) < ITERAZIONI and completo:
        e.ko("iterazioni %s" % testo, det)
    else:
        e.info("iterazioni %s" % testo, det)

    if not completo:
        e.info("", "(con --completo questi diventano controlli, non note)")


# ===========================================================================
# Raccolta
# ===========================================================================

def raccolta(e, righe, diag):
    e.titolo("Integrità della raccolta")

    # --- i due lati si congiungono ---
    senza = diag["unmatched"]
    tot = max(1, diag["rows_client"])
    quota = 100.0 * senza / tot
    if quota <= 2.0:
        e.ok("righe lato client con riscontro sul server",
             "%d su %d (%.2f %% senza)" % (tot - senza, tot, quota))
    else:
        e.ko("righe lato client con riscontro sul server",
             "%.2f %% senza riscontro (%d righe)" % (quota, senza),
             ["di solito: il caricatore fermato prima che i socket si "
              "chiudessero, oppure non agganciato al cgroup di nginx"])

    if diag["only_client"] or diag["only_server"]:
        e.ko("ogni cella ha entrambi i CSV",
             "%d spaiate" % (len(diag["only_client"]) + len(diag["only_server"])),
             ["manca il lato server: %s" % n for n in diag["only_client"]] +
             ["manca il lato client: %s" % n for n in diag["only_server"]])
    else:
        e.ok("ogni cella ha entrambi i CSV", "%d celle" % diag["cells"])

    # --- ogni cella copre tutti e tre i client, con lo stesso numero di giri ---
    per_cella = defaultdict(lambda: defaultdict(int))
    for r in righe:
        per_cella[(r["policy"], r["bw_mbit"], r["obj_label"],
                   r["iteration"])][r["client"]] += 1

    incomplete, disomogenee, pochi = [], [], []
    conteggi = set()
    for cella, per_cl in sorted(per_cella.items()):
        nome = "%s bw%d %s it%02d" % cella
        if set(per_cl) != set(CLIENT):
            incomplete.append("%s: client %s" % (nome, ", ".join(sorted(per_cl))))
            continue
        valori = set(per_cl.values())
        conteggi |= valori
        if len(valori) > 1:
            disomogenee.append("%s: %s" % (nome, dict(per_cl)))
        if min(valori) < GIRI_MINIMI:
            pochi.append("%s: %d giri" % (nome, min(valori)))

    if incomplete:
        e.ko("ogni cella copre h2, h3 e h4", "%d celle incomplete" % len(incomplete),
             incomplete)
    else:
        e.ok("ogni cella copre h2, h3 e h4", "%d celle" % len(per_cella))

    if disomogenee:
        e.ko("stesso numero di giri per i tre client",
             "%d celle sbilanciate" % len(disomogenee), disomogenee)
    else:
        e.ok("stesso numero di giri per i tre client",
             "%s giri" % ", ".join(str(c) for c in sorted(conteggi)))

    if pochi:
        e.ko("almeno %d giri per iterazione" % GIRI_MINIMI,
             "%d celle sotto la soglia" % len(pochi), pochi)
    elif conteggi:
        e.ok("almeno %d giri per iterazione" % GIRI_MINIMI,
             "minimo osservato: %d" % min(conteggi))

    # --- nessuna connessione contata due volte ---
    visti = defaultdict(set)
    doppi = []
    for r in righe:
        k = (r["policy"], r["bw_mbit"], r["obj_label"], r["iteration"])
        chiave = (r["client_ip"], r["port"])
        if chiave in visti[k]:
            doppi.append("%s bw%d %s it%02d: %s:%d" % (k + (chiave[0], chiave[1])))
        visti[k].add(chiave)
    if doppi:
        e.ko("una riga per connessione, senza duplicati",
             "%d duplicati" % len(doppi), doppi)
    else:
        e.ok("una riga per connessione, senza duplicati",
             "%d connessioni" % len(righe))


# ===========================================================================
# Plausibilità
# ===========================================================================

def plausibilita(e, righe):
    e.titolo("Plausibilità delle misure")

    def controlla(nome, predicato, spiegazione=""):
        cattive = [r for r in righe if not predicato(r)]
        if cattive:
            campioni = ["%s bw%d %s it%02d %s:%d" %
                        (r["policy"], r["bw_mbit"], r["obj_label"],
                         r["iteration"], r["client"], r["port"])
                        for r in cattive]
            e.ko(nome, "%d righe su %d" % (len(cattive), len(righe)),
                 ([spiegazione] if spiegazione else []) + campioni)
        else:
            e.ok(nome, "%d righe" % len(righe))

    controlla("mss fra %d e %d byte" % MSS_ATTESO,
              lambda r: MSS_ATTESO[0] <= r["mss"] <= MSS_ATTESO[1],
              "un mss assurdo significa struct disallineate fra kernel e "
              "spazio utente: i dati sarebbero plausibili e sbagliati")
    controlla("RTT di trasporto maggiore di zero", lambda r: r["srtt_ms"] > 0)
    controlla("finestra della route almeno 1 segmento",
              lambda r: r["iw_route"] >= 1)
    controlla("cwnd massima non inferiore alla finestra applicata",
              lambda r: r["max_cwnd"] >= r["iw_applied"])
    controlla("durata della connessione maggiore di zero",
              lambda r: r["duration_ms"] > 0)
    controlla("FCT e goodput maggiori di zero",
              lambda r: r["fct_ms"] > 0 and r["goodput_mbps"] > 0)
    # bytes_acked NON è «i byte trasferiti», ed è un errore facile da fare.
    #
    # Il record esce all'uscita da ESTABLISHED, cioè quando il server manda il
    # FIN: l'ultima finestra di dati è ancora in volo e non riscontrata, quindi
    # il contatore è sistematicamente MINORE dell'oggetto. Non è un difetto
    # della misura ma una conseguenza dell'istante in cui la si prende — lo
    # stesso istante che è stato scelto perché lì tutti i contatori del socket
    # sono ancora leggibili e perché copre le chiusure per reset.
    #
    # La grandezza «byte trasferiti» va quindi letta da size_download lato
    # client, che è esatta. Qui restano due controlli, entrambi fisici:
    # il contatore dev'essere dentro un intervallo sensato — fuori sarebbe
    # spazzatura da struct disallineata — e lo scarto rispetto all'oggetto non
    # può superare i byte che stanno in volo, cioè la finestra di congestione.
    controlla("byte confermati dentro un intervallo sensato",
              lambda r: 0 < r["bytes_acked"] <= r["obj_bytes"] + 8192,
              "fuori da qui il contatore è spazzatura: probabile "
              "disallineamento della struct fra kernel e spazio utente")
    controlla("byte non ancora riscontrati entro la finestra in volo",
              lambda r: r["bytes_acked"] >= r["obj_bytes"]
              - r["max_cwnd"] * r["mss"] - 8192,
              "mancherebbero più byte di quanti possano esserne in volo: "
              "il trasferimento sarebbe stato troncato davvero")
    controlla("oggetto scaricato per intero (lato client)",
              lambda r: r["size_download"] == r["obj_bytes"])


# ===========================================================================
# Comportamento delle politiche
# ===========================================================================

def politiche(e, righe):
    e.titolo("Comportamento delle politiche")

    per_pol = defaultdict(list)
    for r in righe:
        per_pol[r["policy"]].append(r)

    for pol in sorted(per_pol):
        rr = per_pol[pol]
        intervenute = [r for r in rr if r["iw_applied"] != r["iw_route"]]

        if pol in PASSIVE:
            if intervenute:
                e.ko("«%s» non tocca la finestra" % pol,
                     "%d righe su %d con iw_applied != iw_route"
                     % (len(intervenute), len(rr)),
                     ["residuo in iw_map da una corsa precedente: il "
                      "caricatore non è stato riavviato fra una cella e "
                      "l'altra"] +
                     ["%s bw%d %s it%02d: %d -> %d"
                      % (r["policy"], r["bw_mbit"], r["obj_label"],
                         r["iteration"], r["iw_route"], r["iw_applied"])
                      for r in intervenute])
            else:
                e.ok("«%s» non tocca la finestra" % pol,
                     "iw_route == iw_applied su %d righe" % len(rr))
            continue

        # --- politiche che decidono ---
        if not intervenute:
            e.ko("«%s» applica una finestra propria" % pol,
                 "nessuna riga su %d con iw_applied != iw_route" % len(rr),
                 ["la bpf_setsockopt non ha avuto effetto, oppure lo spazio "
                  "utente non ha mai scritto in iw_map"])
        else:
            quota = 100.0 * len(intervenute) / len(rr)
            e.ok("«%s» applica una finestra propria" % pol,
                 "%d righe su %d (%.0f %%)" % (len(intervenute), len(rr), quota))

        # La stima deve muoversi: se «samples» resta fermo, lo spazio utente
        # riceve i record ma non li fa entrare nella media.
        campioni = {r["samples"] for r in rr}
        if len(campioni) <= 1 and rr[0]["samples"] == 0:
            e.att("«%s» aggiorna lo stato della stima" % pol,
                  "samples sempre 0 — atteso solo per le politiche passive")

        if pol.startswith("lossaware"):
            con_perdite = [r for r in rr if r["retrans"] > 0]
            penalizzate = [r for r in rr if r["penalties"] > 0]
            if not con_perdite:
                e.att("«%s» penalizza dove ci sono ritrasmissioni" % pol,
                      "nessuna ritrasmissione osservata: regola non esercitata")
            elif not penalizzate:
                e.ko("«%s» penalizza dove ci sono ritrasmissioni" % pol,
                     "%d connessioni con retrans, 0 penalizzazioni"
                     % len(con_perdite))
            else:
                e.ok("«%s» penalizza dove ci sono ritrasmissioni" % pol,
                     "%d con retrans, %d penalizzazioni"
                     % (len(con_perdite), len(penalizzate)))


# ===========================================================================
# Metriche richieste
# ===========================================================================

RICHIESTE = [
    ("fct_ms", "FCT"),
    ("goodput_mbps", "goodput"),
    ("retrans", "ritrasmissioni"),
    ("srtt_ms", "RTT di trasporto"),
    ("iw_applied", "IW applicata"),
    ("max_cwnd", "cwnd massima"),
]


def metriche(e, outdir):
    e.titolo("Metriche richieste dal protocollo")

    p = os.path.join(outdir, "riepilogo.csv")
    if not os.path.exists(p):
        e.ko("riepilogo.csv prodotto", "assente: eseguire prima stats.py")
        return
    with open(p) as f:
        colonne = f.readline().strip().split(",")

    mancanti = []
    for campo, nome in RICHIESTE:
        for st in ("mean", "median", "std", "p95"):
            c = "%s_%s" % (campo, st)
            if c not in colonne:
                mancanti.append(c)
    if mancanti:
        e.ko("media, mediana, dev. std. e p95 per ogni metrica",
             "%d colonne mancanti" % len(mancanti), mancanti)
    else:
        e.ok("media, mediana, dev. std. e p95 per ogni metrica",
             "%d metriche × 4 statistiche" % len(RICHIESTE))

    if "retrans_flow_pct" in colonne:
        e.ok("percentuale di flussi con retrans > 0", "colonna presente")
    else:
        e.ko("percentuale di flussi con retrans > 0", "colonna assente")

    if "client" in colonne:
        e.ok("metriche separate per h2, h3, h4", "raggruppate per client")
    else:
        e.ko("metriche separate per h2, h3, h4", "colonna «client» assente")

    fra_iter = [c for c in colonne if c.endswith("_median_iter_std")]
    if fra_iter:
        e.ok("dispersione fra le iterazioni", "%d metriche" % len(fra_iter))
    else:
        e.att("dispersione fra le iterazioni", "colonne assenti")

    per_it = sorted(f for f in os.listdir(outdir)
                    if f.startswith("connessioni_it") and f.endswith(".csv"))
    if per_it:
        e.ok("un CSV per iterazione", "%d file: %s … %s"
             % (len(per_it), per_it[0], per_it[-1]))
    else:
        e.ko("un CSV per iterazione", "nessun connessioni_itNN.csv")


# ===========================================================================
# main
# ===========================================================================

def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("results", help="cartella dei risultati della campagna")
    ap.add_argument("--completo", action="store_true",
                    help="pretendi la griglia intera: politiche, bande, "
                         "taglie e iterazioni tutte presenti")
    ap.add_argument("--analisi", default=None,
                    help="cartella dell'analisi (default: <results>/analisi)")
    args = ap.parse_args()

    outdir = args.analisi or os.path.join(args.results, "analisi")

    righe, diag = stats.collect(args.results)
    if not righe:
        sys.exit("Nessuna connessione ricostruita in %s: non c'è niente da "
                 "verificare." % args.results)

    print("%sVerifica di conformità%s — %d connessioni, %d celle, FCT %s"
          % (BOLD, OFF, len(righe), diag["cells"], stats.FCT_DESCRIZIONE))

    e = Esito()
    copertura(e, righe, args.completo)
    raccolta(e, righe, diag)
    plausibilita(e, righe)
    politiche(e, righe)
    metriche(e, outdir)

    print()
    if e.falliti:
        print("%s%d controlli falliti%s, %d passati."
              % (RED, e.falliti, OFF, e.passati))
        sys.exit(1)
    print("%sTutti i %d controlli passati.%s" % (GRN, e.passati, OFF))
    if not args.completo:
        print("La copertura non è stata pretesa: con --completo si verifica "
              "anche che la griglia sia intera.")


if __name__ == "__main__":
    main()
