#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
diagnosi-congestione.py — perché il collo di bottiglia non scarta pacchetti?

    sudo python3 testbed/diagnosi-congestione.py            # 20 Mbit/s, 10 MB
    sudo python3 testbed/diagnosi-congestione.py --bw 20 --obj 10M

Un trasferimento solo, con tutto ciò che serve per capire chi sta limitando
il mittente. Tre sospetti, e ognuno lascia un'impronta diversa:

  1. SCARICAMENTO DELLA SEGMENTAZIONE ancora attivo. Il «limit» del netem
     conta gli skb, non i byte: con GSO acceso un solo skb può valere 64 KB,
     e una coda di venti pacchetti diventa una coda da più di un megabyte, che
     assorbe qualunque raffica. Impronta: ethtool riporta on.

  2. LA CODA NON È DOVE CREDIAMO. Se la disciplina sul collo di bottiglia non
     è quella attesa, o se la strozzatura si forma altrove, i venti pacchetti
     non contano. Impronta: il contatore «dropped» su s1-eth2 resta a zero pur
     essendo il collegamento saturo.

  3. IL MITTENTE È LIMITATO DAL RICEVITORE, non dalla congestione. Se la
     finestra annunciata dal client è più stretta della capacità del percorso,
     i pacchetti in volo non arrivano mai a riempire la coda e la finestra di
     congestione cresce a vuoto. Impronta: «rwnd_limited» in ss -ti diverso da
     zero, e byte in volo molto minori di cwnd × mss.

Va eseguito come root.
"""

import argparse
import os
import re
import sys
import time

QUI = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, QUI)
import testbed as tb  # noqa: E402


def titolo(t):
    print("\n%s==>%s %s" % (tb.BOLD, tb.OFF, t))


def estrai(testo, chiave):
    m = re.search(r"%s[: ](\d+)" % chiave, testo)
    return int(m.group(1)) if m else None


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--bw", type=int, default=20, help="banda del collo di bottiglia")
    ap.add_argument("--obj", default="10M", help="taglia dell'oggetto")
    ap.add_argument("--client", default="h4", help="client che scarica")
    ap.add_argument("--outdir", default=os.path.join(os.path.dirname(QUI), "results"))
    args = ap.parse_args()

    if os.geteuid() != 0:
        sys.exit("Va eseguito come root.")

    bdp = tb.bdp_segments(args.bw, 2 * dict((c[0], c[2]) for c in tb.CLIENTS)[args.client])
    print("%sDiagnosi della congestione%s — %d Mbit/s, oggetto %s, client %s"
          % (tb.BOLD, tb.OFF, args.bw, args.obj, args.client))
    print("    capacità del percorso: %.0f segmenti di prodotto banda-ritardo "
          "+ %d di coda = %.0f"
          % (bdp, tb.BOTTLENECK_QUEUE, bdp + tb.BOTTLENECK_QUEUE))
    print("    oggetto: %d segmenti da %d byte"
          % (-(-tb.object_bytes(args.obj) // tb.MSS), tb.MSS))

    tb.mn_cleanup()
    net = tb.build_net(args.bw)
    nginx = None
    try:
        docroot = tb.make_objects(os.path.join(args.outdir, "_docroot"), [args.obj])
        nginx = tb.start_nginx(net, docroot,
                               os.path.join(args.outdir, "_nginx"),
                               tb.ensure_cgroup())
        server = net.get(tb.SERVER)
        cliente = net.get(args.client)

        # --- sospetto 1: scaricamento della segmentazione ---
        titolo("Sospetto 1 — scaricamento della segmentazione")
        for nodo, dev in ((server, "h1-eth0"), (net.get("s1"), "s1-eth2")):
            out = nodo.cmd("ethtool -k %s 2>/dev/null" % dev)
            righe = [l.strip() for l in out.splitlines()
                     if re.match(r"(tcp|generic|large)-\w*-?offload", l.strip())]
            stato = ", ".join(righe) or "(ethtool non ha risposto)"
            acceso = any(l.endswith(": on") for l in righe)
            print("    %-10s %s" % (dev, stato))
            if acceso:
                print("    %s[att]%s su %s qualcosa è ancora acceso: la coda "
                      "conta skb, non byte." % (tb.YLW, tb.OFF, dev))

        # --- sospetto 2: la disciplina sul collo di bottiglia ---
        titolo("Sospetto 2 — la coda sul collo di bottiglia")
        s1 = net.get("s1")
        print("    configurazione:")
        for l in s1.cmd("tc qdisc show dev s1-eth2").splitlines():
            if l.strip():
                print("      %s" % l.strip())
        prima = s1.cmd("tc -s qdisc show dev s1-eth2")
        scarti_prima = max([int(x) for x in re.findall(r"dropped (\d+)", prima)]
                           or [0])

        # --- il trasferimento, con campionamento dello stato del socket ---
        titolo("Trasferimento e stato del mittente")
        cliente.cmd("curl -s -o /dev/null http://%s/%s > /tmp/diag_curl 2>&1 &"
                    % (tb.SERVER_IP, tb.object_name(args.obj)))
        campioni = []
        for _ in range(14):
            time.sleep(0.25)
            out = server.cmd("ss -tin state established '( sport = :80 )' 2>/dev/null")
            if "cwnd" in out:
                campioni.append(out)
        cliente.cmd("wait")

        if not campioni:
            print("    nessun campione: il trasferimento è finito troppo presto, "
                  "prova un oggetto più grande o una banda più bassa.")
        else:
            ultimo = campioni[len(campioni) // 2]
            print("    stato a metà trasferimento:")
            for l in ultimo.splitlines():
                if l.strip() and not l.startswith("State"):
                    print("      %s" % l.strip()[:150])
            cwnd = max(filter(None, (estrai(c, "cwnd") for c in campioni)),
                       default=None)
            unacked = max(filter(None, (estrai(c, "unacked") for c in campioni)),
                          default=None)
            rwnd_lim = max(filter(None, (estrai(c, "rwnd_limited") for c in campioni)),
                           default=0)
            print()
            print("    cwnd massima osservata      : %s segmenti" % cwnd)
            print("    byte in volo massimi        : %s segmenti"
                  % (unacked if unacked is not None else "n/d"))
            print("    tempo limitato dal ricevitore: %s" % (rwnd_lim or "0"))

        # --- il verdetto della coda ---
        titolo("Sospetto 3 — chi ha limitato il mittente")
        dopo = s1.cmd("tc -s qdisc show dev s1-eth2")
        # Il MASSIMO, non la somma: htb e netem sono padre e figlio sulla
        # stessa interfaccia, e lo scarto avviene nel netem ma viene contato
        # da entrambi. Sommandoli si conta due volte lo stesso pacchetto.
        scarti_dopo = max([int(x) for x in re.findall(r"dropped (\d+)", dopo)]
                          or [0])
        scarti = scarti_dopo - scarti_prima
        print("    contatori del collo di bottiglia dopo il trasferimento:")
        for l in dopo.splitlines():
            if l.strip():
                print("      %s" % l.strip())
        print()
        if scarti > 0:
            print("    %s[ok]%s il collo di bottiglia ha scartato %d pacchetti: "
                  "la congestione c'è." % (tb.GRN, tb.OFF, scarti))
            print("         Se «retrans» nei CSV resta zero, il problema è a valle: "
                  "le perdite non arrivano al mittente o non le stiamo leggendo.")
        else:
            print("    %s[att]%s nessuno scarto sul collo di bottiglia."
                  % (tb.YLW, tb.OFF))
            print("         Il mittente non ha mai riempito la coda. Guarda sopra: "
                  "se i byte in volo sono molto meno di cwnd, a limitare è la")
            print("         finestra del ricevitore, non la congestione — e allora "
                  "l'esperimento sta misurando il ricevitore.")
    finally:
        if nginx:
            tb.stop_nginx(nginx, tb.ensure_cgroup())
        net.stop()


if __name__ == "__main__":
    main()
