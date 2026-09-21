#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
banda-massima.py — fin dove il banco regge davvero?

    sudo python3 testbed/banda-massima.py
    sudo python3 testbed/banda-massima.py --valori 100,150,200,300

La taratura ha mostrato che a 1000 Mbit/s nominali iperf3 ne misura 37,8:
il collo di bottiglia dichiarato non è più il collo di bottiglia, e la banda
«alta» della griglia finisce sotto quella «media». Prima di scegliere tre
valori nuovi serve sapere due cose:

  1. il TETTO DELLA MACCHINA — quanto passa fra due host senza alcun
     limitatore. È il muro oltre il quale nessun valore nominale ha senso;
  2. fino a che valore il LIMITATORE INSEGUE il nominale. Un valore che
     l'HTB non riesce a realizzare non è una condizione sperimentale: è
     rumore travestito da parametro.

Misura con iperf3 dal client più vicino (h2, RTT 6 ms), così la finestra di
ricezione e la crescita della finestra di congestione non entrano nel conto e
resta solo la capacità del percorso.

Va eseguito come root.
"""

import argparse
import json
import os
import sys
import time

QUI = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, QUI)
import testbed as tb  # noqa: E402

DURATA = 6          # secondi per punto


def misura(net, etichetta):
    """Una corsa di iperf3 da h2 al server. Restituisce Mbit/s, o nan."""
    srv = net.get(tb.SERVER)
    srv.popen(["iperf3", "-s", "-1", "-p", "5201"])
    time.sleep(0.6)
    out = net.get("h2").cmd("iperf3 -c %s -p 5201 -t %d -J 2>/dev/null"
                            % (tb.SERVER_IP, DURATA))
    try:
        j = json.loads(out[out.index("{"):out.rindex("}") + 1])
        return j["end"]["sum_received"]["bits_per_second"] / 1e6
    except Exception:       # noqa: BLE001
        return float("nan")


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--valori", default="20,50,100,150,200,300,500,1000",
                    help="valori nominali da provare, separati da virgole")
    ap.add_argument("--senza-limite", action="store_true", default=True,
                    help="misura anche il tetto della macchina (predefinito)")
    ap.add_argument("--quantum", type=int, default=None,
                    help="quantum della classe HTB in byte, imposto alla "
                         "COSTRUZIONE della topologia. 0 ripristina il "
                         "comportamento predefinito di Mininet, con l'avviso "
                         "«quantum of class is big». Serve a confrontare le "
                         "due configurazioni sullo stesso banco.")
    args = ap.parse_args()

    if os.geteuid() != 0:
        sys.exit("Va eseguito come root.")

    valori = [int(x) for x in args.valori.split(",")]

    # Il quantum va deciso PRIMA di costruire la topologia: entra nel comando
    # che crea la classe HTB, non si applica dopo. Modificarlo a posteriori con
    # «tc class change» dà un esito ambiguo — è l'errore che avevo fatto nella
    # prima versione di questo script.
    if args.quantum is not None:
        tb.HTB_QUANTUM = args.quantum or None
    print("%sBanda realmente raggiungibile%s — iperf3 da h2, %d s per punto"
          % (tb.BOLD, tb.OFF, DURATA))
    print("    quantum della classe HTB: %s\n"
          % ("%d byte" % tb.HTB_QUANTUM if tb.HTB_QUANTUM
             else "lasciato a tc (rate/r2q)"))

    # --- il tetto della macchina: topologia costruita e poi disarmata -------
    tetto = float("nan")
    if args.senza_limite:
        tb.mn_cleanup()
        net = tb.build_net(valori[-1])
        try:
            s1, s2 = net.get("s1"), net.get("s2")
            s1.cmd("tc qdisc del dev s1-eth2 root 2>/dev/null")
            s2.cmd("tc qdisc del dev s2-eth1 root 2>/dev/null")
            tetto = misura(net, "senza limite")
        finally:
            net.stop()
        print("    %-14s %10.1f Mbit/s   <- il muro della macchina virtuale"
              % ("nessun limite", tetto))
        print()

    print("    %-14s %12s %10s   %s"
          % ("nominale", "misurata", "resa", "giudizio"))
    risultati = {}
    for bw in valori:
        tb.mn_cleanup()
        net = tb.build_net(bw)
        try:
            got = misura(net, str(bw))
        finally:
            net.stop()
        risultati[bw] = got
        resa = 100.0 * got / bw if bw else 0.0
        if resa >= 90:
            giudizio = "%susabile%s" % (tb.GRN, tb.OFF)
        elif resa >= 75:
            giudizio = "%sal limite%s" % (tb.YLW, tb.OFF)
        else:
            giudizio = "%sda scartare%s" % (tb.RED, tb.OFF)
        print("    %-14s %10.1f Mb %9.0f%%   %s"
              % ("%d Mbit/s" % bw, got, resa, giudizio))

    # --- proposta ----------------------------------------------------------
    usabili = [bw for bw, got in risultati.items() if got >= 0.90 * bw]
    print()
    if not usabili:
        print("    Nessun valore realizzato entro il 10 %: il banco non "
              "shapa in modo affidabile.")
        return
    alto = max(usabili)
    print("    Il valore più alto che il limitatore realizza fedelmente è "
          "%d Mbit/s." % alto)
    print("    Una terna coerente, bassa / media / alta, potrebbe essere:")
    print("        %d, %d, %d Mbit/s"
          % (max(5, alto // 20), max(10, alto // 5), alto))
    print()
    print("    Da riportare in tesi accanto ai valori scelti: il banco è "
          "virtualizzato,")
    print("    e sopra %d Mbit/s il limitatore non insegue più il valore "
          "nominale." % alto)
    if tetto == tetto:      # non è nan
        print("    Il tetto della macchina, senza alcun limitatore, è "
              "%.0f Mbit/s." % tetto)


if __name__ == "__main__":
    main()
