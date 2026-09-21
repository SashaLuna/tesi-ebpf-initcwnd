#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
testbed.py — topologia, protocollo sperimentale e orchestrazione della
campagna di misura per augmenter.

Sottocomandi
------------
  check       costruisce la topologia, verifica RTT e banda, stampa la
              tabella dei parametri derivati e smonta tutto. Un minuto.
  traffico    IL GIRO CORTO: costruisce la topologia, esegue lo scambio di
              pacchetti e scrive il CSV lato client. Il caricatore lo avvii
              tu, a mano, in un altro terminale. Un esperimento alla volta.
  calibrate   misura la banda effettivamente raggiungibile con iperf3 e
              esplora i valori della finestra statica alta, scrivendo la
              raccomandazione in calibration.json.
  run         la campagna intera: è «traffico» ripetuto su tutta la griglia,
              avviando e fermando il caricatore da sé a ogni cella.
  shell       lascia aperta la CLI di Mininet sulla topologia, per ispezione.

Topologia
---------
             (banda variabile, coda 20 pacchetti)
  h1 ──── s1 ═══════════════════════════════════ s2 ──── h2   RTT ≈  6 ms
  server                 collo di bottiglia       │  ──── h3   RTT ≈ 22 ms
  (eBPF)                                          └  ──── h4   RTT ≈ 52 ms

Il collo di bottiglia è il collegamento s1–s2 e la coda che conta è quella di
s1 verso s2, cioè quella attraversata dal traffico del server verso i client.
I ritardi stanno sui collegamenti d'accesso, non sul collo di bottiglia: se
stessero là, il limite di coda a 20 pacchetti del netem limiterebbe anche i
pacchetti in volo e il collegamento non sarebbe più una strozzatura di banda
ma di finestra.

Va eseguito come root.
"""

import argparse
import json
import math
import os
import re
import shutil
import signal
import statistics
import subprocess
import sys
import time

try:
    from mininet.net import Mininet
    from mininet.topo import Topo
    from mininet.link import TCLink, TCIntf, Link
    from mininet.node import OVSBridge
    from mininet.log import setLogLevel
    from mininet.cli import CLI
    from mininet.clean import cleanup as mn_cleanup
except ImportError:
    sys.exit("Mininet non trovato. Eseguire prima testbed/00-install.sh")


# ===========================================================================
# Il quantum della classe HTB
# ===========================================================================
#
# Mininet costruisce la classe HTB senza dire il quantum, e tc allora se lo
# ricava da rate/r2q, con r2q predefinito a 10. Sopra i 16 Mbit/s il valore
# supera il tetto di 200 000 byte: tc avverte — «quantum of class 50001 is
# big. Consider r2q change» — e lo tronca. Mininet stampa quell'avviso con il
# prefisso «*** Error:», che è suo e non di tc, perché non distingue fra
# errore e avviso su ciò che i comandi scrivono sullo standard error.
#
# Non è cosmesi. Alle nostre tre bande il limitatore realizza comunque il 91-94
# per cento del nominale, quindi l'avviso è innocuo QUI; ma tre giorni passati
# a ignorare righe che cominciano con «Error» sono tre giorni in cui un errore
# vero può nascondersi in mezzo e non essere visto.
#
# Un quantum dell'ordine dell'MTU fa servire la classe un pacchetto per volta
# invece che a mazzi — che è anche ciò che il netem da venti pacchetti a valle
# può reggere.
#
# Metterlo a None ripristina il comportamento di Mininet, avviso compreso: è
# utile per confrontare le due configurazioni.
HTB_QUANTUM = 1514


class IntfConQuantum(TCIntf):
    """TCIntf che aggiunge «quantum» al comando che crea la classe HTB."""

    def bwCmds(self, **kwargs):
        cmds, parent = TCIntf.bwCmds(self, **kwargs)
        if HTB_QUANTUM:
            cmds = [c + " quantum %d" % HTB_QUANTUM
                    if ("class add" in c and " htb " in c) else c
                    for c in cmds]
        return cmds, parent


class TCLinkQuantum(Link):
    """TCLink identico all'originale, ma con l'interfaccia di sopra.

    TCLink fissa cls1 e cls2 dentro il proprio costruttore e non li lascia
    scegliere, quindi non basta passargliene altri: va rifatto il costruttore.
    """

    def __init__(self, node1, node2, port1=None, port2=None,
                 intfName1=None, intfName2=None, addr1=None, addr2=None,
                 **params):
        Link.__init__(self, node1, node2, port1=port1, port2=port2,
                      intfName1=intfName1, intfName2=intfName2,
                      cls1=IntfConQuantum, cls2=IntfConQuantum,
                      addr1=addr1, addr2=addr2,
                      params1=params, params2=params)


# ===========================================================================
# Parametri del banco di prova
# ===========================================================================

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
# Cartella che contiene le sottocartelle delle politiche, ognuna col proprio
# eseguibile: politiche/static10/augmenter, politiche/ewma/augmenter, ...
# Si sovrascrive con --aug-dir.
AUG_DIR = os.path.join(ROOT, "politiche")


def policy_bin(policy):
    """Percorso dell'eseguibile di una politica."""
    return os.path.join(AUG_DIR, POLICIES[policy]["bin"], "augmenter")


def policy_available(policy):
    return os.path.exists(policy_bin(policy))

SERVER = "h1"
SERVER_IP = "10.0.0.1"

# (nome, indirizzo, ritardo per interfaccia).  Il ritardo è applicato a
# entrambi i lati del collegamento d'accesso, quindi il contributo al RTT è il
# doppio.  A questo si aggiungono la latenza di serializzazione e l'attesa in
# coda sul collo di bottiglia, che dipendono dalla banda.
CLIENTS = [
    ("h2", "10.0.0.2", 3),    # RTT nominale  6 ms
    ("h3", "10.0.0.3", 11),   # RTT nominale 22 ms
    ("h4", "10.0.0.4", 26),   # RTT nominale 52 ms
]

# Le tre bande, scelte DOPO averle misurate e non prima.
#
# iperf3 sul banco dà: 20 -> 18,8 (94 %), 50 -> 46,9 (94 %), 100 -> 91,4 (91 %),
# 150 -> 126,5 (84 %), 200 -> 149,3 (75 %), 300 -> 33,1 (11 %), 1000 -> 39,6 (4 %).
# La macchina in sé regge 5,5 Gbit/s senza limitatore: il tetto non è
# l'hardware ma il limitatore, che oltre i 200 Mbit/s smette di inseguire il
# valore nominale e sopra i 300 crolla.
#
# I 1000 Mbit/s della proposta iniziale davano 37,8 Mbit/s reali, cioè MENO
# della cella «media»: l'ordine basso/medio/alto era rotto. Questi tre valori
# sono realizzati fedelmente e sono monotoni davvero.
BANDWIDTHS = [20, 50, 100]            # Mbit/s sul collo di bottiglia
BOTTLENECK_QUEUE = 20                 # pacchetti, come da protocollo
ACCESS_QUEUE = 20000                  # pacchetti: il netem d'accesso deve
                                      # poter contenere i pacchetti in volo,
                                      # altrimenti scarta al posto del collo
                                      # di bottiglia

OBJECTS = [                           # (etichetta, byte)
    ("1K",    1 * 1024),
    ("10K",  10 * 1024),
    ("30K",  30 * 1024),
    ("200K", 200 * 1024),
    ("1M",    1 * 1024 * 1024),
    ("10M",  10 * 1024 * 1024),
]

MSS = 1448          # MTU 1500 − 20 (IP) − 32 (TCP con marca temporale)
ROUNDS = 15         # giri per iterazione: ogni giro è una richiesta per client
ITERATIONS = 10     # ripetizioni dell'esperimento
ROUND_SLEEP = 0.2   # pausa fra un giro e il successivo, secondi
CURL_TIMEOUT = 120  # secondi

HTTP_PORT = 80
CGROUP = "/sys/fs/cgroup/augmenter"

# Oggetto minuscolo servito sempre, qualunque taglia chieda la cella: è quello
# con cui start_nginx() verifica che il server risponda. Vedi make_objects().
PROBE_NAME = "probe.bin"

# Tetto assoluto della saturazione superiore. Il valore per cella è il
# prodotto banda-ritardo più la coda, ma a 1 Gbit/s con 52 ms di RTT quel
# calcolo dà oltre 4400 segmenti: una finestra iniziale da 6,5 MB. Il tetto
# serve a tenere l'esperimento in un intervallo interpretabile ed è esso stesso
# un parametro da dichiarare.
# Con le bande misurate la saturazione superiore massima vale 469 segmenti
# (h4 a 100 Mbit/s), quindi questo tetto non entra mai in gioco. Resta come
# rete di sicurezza per chi rilanciasse la campagna con bande più alte, ma NON
# è più un parametro da dichiarare in tesi: la saturazione segue sempre il
# prodotto banda-ritardo più la coda.
IW_MAX_CEILING = 1000
# Il pavimento della stima e' la finestra che il kernel userebbe da solo.
# Una politica non deve poter fare PEGGIO dell'astensione: sugli oggetti da
# 1 MB a 100 Mbit/s ogni connessione ritrasmette, la politica 4 dimezza a
# ogni giro e con il pavimento a 4 finiva SOTTO il riferimento. Adesso, nel
# caso peggiore, si comporta come «static10».
IW_MIN = 10

# Soglia del discriminante di «lossaware-disc», in percentuale di iw_applied:
# sopra questa crescita la perdita non viene attribuita alla finestra iniziale.
# Sui record misurati la separazione e' netta e 150 sta in mezzo:
#   da penalizzare      141/141 = 100 %   66/66 = 100 %   44/33 = 133 %
#   da non penalizzare   65/17  = 382 %   70/10 = 700 %   62/4  = 1550 %
CRESCITA_MAX = 150

# --- le politiche in confronto ---------------------------------------------
# initcwnd : valore imposto sulla route di h1 (None = dalla taratura)
# metrics  : se lasciare attiva la cache tcp_metrics
# bin      : sottocartella con l'eseguibile di quella politica
# extra    : opzioni proprie di quella politica; {iw_min}, {iw_max}, {alpha} e
#            {thresh} sono sostituiti per cella. Le tre configurazioni di
#            riferimento usano lo STESSO binario (static10), che osserva e
#            basta: fra loro cambiano solo la route e il sysctl.
POLICIES = {
    "static10": dict(
        desc="Riferimento: finestra iniziale predefinita, 10 segmenti",
        initcwnd=10, metrics=False, bin="static10", extra=[]),
    "metrics": dict(
        desc="Riferimento: predefinita con cache tcp_metrics attiva",
        initcwnd=10, metrics=True, bin="static10", extra=[]),
    "statichigh": dict(
        desc="Riferimento: finestra statica alta, imposta sulla route di h1",
        initcwnd=None, metrics=False, bin="static10", extra=[]),
    "ewma": dict(
        desc="eBPF: media mobile esponenziale della cwnd massima",
        initcwnd=10, metrics=False, bin="ewma",
        extra=["--iw-min", "{iw_min}", "--iw-max", "{iw_max}",
               "--alpha-shift", "{alpha}"]),
    "lossaware": dict(
        desc="eBPF: media mobile esponenziale sensibile alle ritrasmissioni",
        initcwnd=10, metrics=False, bin="lossaware",
        extra=["--iw-min", "{iw_min}", "--iw-max", "{iw_max}",
               "--alpha-shift", "{alpha}", "--retrans-thresh", "{thresh}"]),

    # --- fuori dalla griglia principale ------------------------------------
    # Misura il COSTO DEL PERCORSO eBPF, non un'altra politica: impone la
    # stessa finestra di «statichigh», ma passando da bpf_setsockopt() invece
    # che dalla route. La differenza fra le due è il costo del programma,
    # isolato dal beneficio della finestra.
    #
    # --dst precarica iw_map con gli indirizzi dei client: senza, la prima
    # connessione verso ciascuno non troverebbe la chiave e partirebbe con la
    # finestra della route — sarebbe «statica dalla seconda in poi», che non è
    # la stessa cosa di «ip route initcwnd N» e renderebbe il confronto
    # scorretto proprio nel punto che si vuole confrontare.
    # La variante proposta: stessa regola, ma le perdite vengono attribuite
    # alla finestra iniziale SOLO se la connessione ha perso prima che la cwnd
    # crescesse (--crescita-max, in percentuale di iw_applied). Serve perche'
    # la regola pura si autodistrugge dove la perdita e' strutturale: sugli
    # oggetti da 1 MB a 100 Mbit/s lo slow start supera sempre la capacita' del
    # percorso, quindi ogni connessione ritrasmette, quindi la stima viene
    # dimezzata a ogni giro fino al pavimento. Misurato: stima media 4,1
    # segmenti su h2 e h3, con il 100 % dei flussi in perdita comunque.
    #
    # Sta nella griglia principale accanto a «lossaware», non al posto suo: il
    # confronto fra la specifica e la variante e' esso stesso un risultato.
    "lossaware-disc": dict(
        desc="eBPF: come lossaware, ma non attribuisce alla finestra iniziale "
             "le perdite avvenute dopo che la finestra era gia' cresciuta",
        initcwnd=10, metrics=False, bin="lossaware",
        extra=["--iw-min", "{iw_min}", "--iw-max", "{iw_max}",
               "--alpha-shift", "{alpha}", "--retrans-thresh", "{thresh}",
               "--crescita-max", "{crescita}"]),

    "statichigh-bpf": dict(
        desc="eBPF: la stessa finestra statica alta, imposta dal programma",
        initcwnd=10, metrics=False, bin="statichigh-bpf",
        extra=["--iw", "{static_high}", "--dst", "{dst}"]),
}

# L'ordine della griglia principale. «statichigh-bpf» NON c'è dentro di
# proposito: è una misura di metodo, non una delle cinque configurazioni a
# confronto, e non merita di allungare del venti per cento una campagna di
# sette ore. Si esegue a parte, su poche celle:
#
#   run --policies statichigh,statichigh-bpf --objects 200K --iterations 5
#
POLICY_ORDER = ["static10", "metrics", "statichigh", "ewma", "lossaware",
                "lossaware-disc"]

PROFILES = {
    "quick": dict(bandwidths=[20, 100], objects=["10K", "200K", "1M"],
                  iterations=3, rounds=10,
                  policies=["static10", "statichigh", "ewma", "lossaware",
                            "lossaware-disc"]),
    "full":  dict(bandwidths=BANDWIDTHS, objects=[o[0] for o in OBJECTS],
                  iterations=ITERATIONS, rounds=ROUNDS,
                  policies=POLICY_ORDER),
}

NGINX_CONF = """
# Generato da testbed.py — non modificare a mano.
daemon off;
worker_processes 2;

# I lavoratori girano come root. Sull'installazione di sistema girerebbero come
# www-data, che non può attraversare la home dell'utente (spesso 750) e
# risponderebbe 403 invece di servire l'oggetto. Su un banco di prova isolato
# non è un problema di sicurezza ed elimina un'intera classe di guasti.
user root;

error_log {prefix}/error.log info;
pid {prefix}/nginx.pid;
events {{ worker_connections 1024; }}
http {{
    access_log off;

    # Percorso dei file temporanei dentro il prefisso: quello predefinito è
    # /var/lib/nginx, che il pacchetto potrebbe non aver creato.
    client_body_temp_path {prefix}/tmp_body;

    sendfile on;
    tcp_nodelay on;
    tcp_nopush off;
    gzip off;

    # keepalive_timeout 0 è il parametro che rende sensato tutto
    # l'esperimento: senza, il client riuserebbe la stessa connessione per i
    # quindici giri e la finestra iniziale verrebbe applicata una volta sola.
    # Con 0, ogni richiesta è una connessione nuova, cioè un'osservazione.
    keepalive_timeout 0;
    keepalive_requests 1;

    server {{
        listen {port} backlog=4096;
        root {docroot};
        server_name _;
        location / {{ }}
    }}
}}
"""


# ===========================================================================
# Utilità
# ===========================================================================

BOLD, GRN, YLW, RED, OFF = "\033[1m", "\033[32m", "\033[33m", "\033[31m", "\033[0m"


def say(msg):
    print("%s==>%s %s" % (BOLD, OFF, msg), flush=True)


def note(msg):
    print("    %s" % msg, flush=True)


def warn(msg):
    print("    %s[att]%s %s" % (YLW, OFF, msg), flush=True)


def human_time(seconds):
    seconds = int(seconds)
    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, 60)
    if h:
        return "%d h %02d min" % (h, m)
    if m:
        return "%d min %02d s" % (m, s)
    return "%d s" % s


def bdp_segments(bw_mbit, rtt_ms):
    """Prodotto banda-ritardo espresso in segmenti da MSS byte."""
    return (bw_mbit * 1e6 * rtt_ms / 1000.0 / 8.0) / MSS


def iw_max_for(bw_mbit, ceiling=IW_MAX_CEILING):
    """Saturazione superiore della stima per una cella.

    Calcolata sul client con il RTT più alto, perché è quello che ha il
    prodotto banda-ritardo maggiore: tarare sul client più vicino
    taglierebbe la politica proprio dove ha più margine. Alla capacità del
    percorso si somma la coda del collo di bottiglia, che è memoria
    disponibile a tutti gli effetti.
    """
    rtt_max = 2 * max(c[2] for c in CLIENTS)   # ms, andata e ritorno
    value = bdp_segments(bw_mbit, rtt_max) + BOTTLENECK_QUEUE
    return int(max(10, min(ceiling, math.ceil(value))))


def object_name(label):
    return "obj_%s.bin" % label


def run_id_di(policy, bw, label, iteration):
    """Il nome di una cella. Unico posto in cui è definito.

    stats.py appaia i due lati per NOME DI FILE — client_<run_id>.csv con
    server_<run_id>.csv — quindi questa forma è un contratto fra i due lati
    della misura, non una comodità: se il giro corto e la campagna la
    scrivessero diversamente, i CSV non si congiungerebbero e l'analisi direbbe
    «nessuna connessione ricostruita» pur avendo i dati sotto gli occhi.
    """
    return "%s_bw%d_%s_it%02d" % (policy, bw, label, iteration)


def object_bytes(label):
    return dict(OBJECTS)[label]


# ===========================================================================
# Topologia
# ===========================================================================

class DumbbellTopo(Topo):
    """h1 ── s1 ══ s2 ── {h2,h3,h4}; il collo di bottiglia è s1–s2."""

    def build(self, bw=100, queue=BOTTLENECK_QUEUE):
        h1 = self.addHost(SERVER, ip="%s/24" % SERVER_IP)
        s1 = self.addSwitch("s1")
        s2 = self.addSwitch("s2")

        # Accesso del server: NESSUN limite di banda e nessuna disciplina.
        #
        # Limitarlo a 1000 Mbit/s sarebbe un errore, e sottile: nella cella a
        # 1 Gbit/s questo collegamento e il collo di bottiglia avrebbero la
        # stessa velocità, e la coda si formerebbe QUI — dove ne avremmo mille
        # pacchetti — invece che su s1 verso s2, dove il protocollo ne vuole
        # venti. Le perdite avverrebbero nel posto sbagliato e la cella più
        # veloce misurerebbe un'altra cosa. Senza limite, il collo di
        # bottiglia è l'unico punto in cui si accodano pacchetti.
        self.addLink(h1, s1)

        # IL collo di bottiglia. Nessun ritardo qui: il limite di coda del
        # netem vale per la sola strozzatura e non deve contenere anche i
        # pacchetti in volo dovuti alla latenza.
        self.addLink(s1, s2, bw=bw, max_queue_size=queue)

        # Accessi dei client: solo ritardo, nessun limite di banda. Il limite
        # di coda è largo perché a 1 Gbit/s e 26 ms i pacchetti in volo sono
        # migliaia e il valore predefinito del netem (1000) li scarterebbe.
        for name, ip, delay in CLIENTS:
            h = self.addHost(name, ip="%s/24" % ip)
            self.addLink(h, s2, delay="%dms" % delay,
                         max_queue_size=ACCESS_QUEUE)


def build_net(bw, queue=BOTTLENECK_QUEUE):
    """Costruisce e avvia la rete. OVSBridge = commutatore ad apprendimento
    autonomo: nessun controllore esterno da avviare, un pezzo in meno che può
    non partire nel mezzo di una campagna di ore."""
    topo = DumbbellTopo(bw=bw, queue=queue)
    net = Mininet(topo=topo,
                  link=TCLinkQuantum if HTB_QUANTUM else TCLink,
                  switch=OVSBridge,
                  controller=None, autoSetMacs=True, autoStaticArp=True,
                  waitConnected=False)
    net.start()
    tune_hosts(net)
    loss = net.pingAll(timeout="1")
    if loss:
        warn("perdita %.0f %% al ping iniziale: la topologia non e' pulita" % loss)
    return net


def tune_hosts(net):
    """Parametri per spazio dei nomi. net.ipv4.* è per spazio dei nomi di rete
    e quindi va impostato host per host; net.core.* non lo è ed è stato
    impostato una volta sola da 00-install.sh."""
    server = net.get(SERVER)

    # Scaricamento della segmentazione disattivato ovunque: con TSO/GSO attivi
    # il mittente consegna alla scheda segmenti da decine di kilobyte e la
    # dimensione effettiva della raffica iniziale non corrisponde più alla
    # finestra in segmenti che stiamo misurando.
    for node in net.hosts + net.switches:
        for intf in node.intfList():
            if intf.name != "lo":
                node.cmd("ethtool -K %s tso off gso off gro off lro off "
                         ">/dev/null 2>&1" % intf.name)

    # Server: buffer di trasmissione capaci di contenere il prodotto
    # banda-ritardo peggiore (1 Gbit/s × 52 ms ≈ 6,5 MB), altrimenti sarebbe
    # il buffer, non la finestra di congestione, a limitare il trasferimento.
    server.cmd("sysctl -q -w net.ipv4.tcp_wmem='4096 65536 67108864'")
    server.cmd("sysctl -q -w net.ipv4.tcp_congestion_control=cubic")
    server.cmd("sysctl -q -w net.ipv4.tcp_slow_start_after_idle=0")
    server.cmd("sysctl -q -w net.ipv4.tcp_timestamps=1")
    server.cmd("sysctl -q -w net.ipv4.tcp_sack=1")

    for name, _ip, _d in CLIENTS:
        h = net.get(name)
        h.cmd("sysctl -q -w net.ipv4.tcp_rmem='4096 131072 67108864'")
        h.cmd("sysctl -q -w net.ipv4.tcp_congestion_control=cubic")
        h.cmd("sysctl -q -w net.ipv4.tcp_timestamps=1")
        h.cmd("sysctl -q -w net.ipv4.tcp_sack=1")
        # Finestra di ricezione ampia: se il ricevitore annuncia poco, la
        # finestra iniziale grande non serve a niente e si misurerebbe il
        # ricevitore invece del mittente.
        h.cmd("sysctl -q -w net.ipv4.tcp_adv_win_scale=1")


# ===========================================================================
# Documenti serviti e server HTTP
# ===========================================================================

def make_objects(docroot, labels):
    os.makedirs(docroot, exist_ok=True)

    # Oggetto di servizio, indipendente dalle taglie richieste: start_nginx()
    # lo usa per accorgersi che il server risponde.
    #
    # Deve esistere SEMPRE. Provando la prontezza con una delle taglie della
    # griglia, una cella che non la comprende — «traffico --obj 200K», o il
    # profilo «quick», che non hanno la taglia da 1 K — riceverebbe 404 e la
    # prova concluderebbe a torto che nginx non è partito. È un guasto
    # particolarmente insidioso perché il registro di nginx mostra il server
    # vivo che risponde: la diagnosi punta nella direzione sbagliata.
    probe = os.path.join(docroot, PROBE_NAME)
    if not os.path.exists(probe):
        with open(probe, "wb") as f:
            f.write(b"ok\n")

    for label in labels:
        path = os.path.join(docroot, object_name(label))
        size = object_bytes(label)
        if os.path.exists(path) and os.path.getsize(path) == size:
            continue
        # Contenuto casuale: qualunque compressione lungo il percorso — non ce
        # ne sono, ma è una garanzia a costo zero — non altererebbe i byte
        # effettivamente trasmessi.
        with open(path, "wb") as f:
            f.write(os.urandom(size))
    return docroot


def ensure_cgroup():
    """Crea il cgroup dedicato al server. Agganciare il programma alla radice
    di /sys/fs/cgroup funzionerebbe, ma sottoporrebbe al programma ogni
    apertura passiva della macchina: un cgroup dedicato circoscrive il
    perimetro a nginx e ai suoi processi figli, che lo ereditano."""
    try:
        os.makedirs(CGROUP, exist_ok=True)
        with open(os.path.join(CGROUP, "cgroup.procs"), "a"):
            pass
        return CGROUP
    except OSError as e:
        warn("cgroup dedicato non creabile (%s): uso la radice /sys/fs/cgroup. "
             "Le misure restano valide, il perimetro è solo più largo." % e)
        return "/sys/fs/cgroup"


def verifica_cgroup(cgroup, startlog):
    """nginx è DAVVERO entrato nel cgroup?

    Se non c'è, il programma eBPF non vede nessuna connessione e il CSV lato
    server resta con la sola intestazione. È il guasto peggiore di tutti,
    perché non interrompe niente: la campagna gira per ore, i CSV lato client
    si riempiono regolarmente, e ci si accorge del disastro solo in analisi.
    Meglio un avviso rumoroso adesso.
    """
    try:
        with open(os.path.join(cgroup, "cgroup.procs")) as f:
            membri = [l.strip() for l in f if l.strip()]
    except OSError as e:
        warn("non riesco a leggere %s/cgroup.procs (%s)" % (cgroup, e))
        return False

    if membri:
        note("nginx nel cgroup %s — %d processi" % (cgroup, len(membri)))
        return True

    warn("IL CGROUP %s È VUOTO: nginx non ci è entrato." % cgroup)
    warn("Il programma eBPF non vedrà nessuna connessione e il CSV lato")
    warn("server resterà con la sola intestazione. Non ha senso misurare.")
    if os.path.exists(startlog):
        coda = open(startlog).read().strip().splitlines()[-5:]
        for riga in coda:
            note("  %s" % riga)
    return False


def start_nginx(net, docroot, prefix, cgroup):
    # PERCORSI ASSOLUTI, sempre. nginx risolve il file indicato da -c
    # RISPETTO al prefisso indicato da -p, e fa lo stesso con la direttiva
    # «root»: passandogli percorsi relativi si ottiene «results/x/results/x/…»,
    # cioè un file che non esiste, e un messaggio d'errore che non lascia
    # capire da dove venga il raddoppio.
    prefix = os.path.abspath(prefix)
    docroot = os.path.abspath(docroot)

    os.makedirs(prefix, exist_ok=True)
    conf = os.path.join(prefix, "nginx.conf")
    with open(conf, "w") as f:
        f.write(NGINX_CONF.format(prefix=prefix, docroot=docroot,
                                  port=HTTP_PORT))
    server = net.get(SERVER)

    # --- la gerarchia cgroup2 dentro lo spazio dei nomi dell'host ---------
    #
    # Mininet avvia gli host con «mnexec -n», che disfa insieme allo spazio dei
    # nomi di RETE anche quello di MOUNT, e poi rimonta sysfs su /sys perché
    # /sys/class/net rifletta la rete nuova. Effetto collaterale: la gerarchia
    # cgroup2, che stava montata sotto il vecchio /sys, sparisce dalla vista di
    # h1. Il caricatore, che gira fuori, la vede; nginx, che gira dentro, no —
    # e il tentativo di entrare nel cgroup fallisce con «Directory nonexistent».
    #
    # Rimontarla qui la rimette a disposizione. Non è una copia: cgroup2 è una
    # gerarchia sola per spazio dei nomi cgroup, e mnexec quello non lo disfa,
    # quindi è esattamente la stessa che vede il caricatore. La montiamo solo
    # se non c'è già (cgroup.controllers esiste alla radice di ogni cgroup2).
    mnt = server.cmd("test -e /sys/fs/cgroup/cgroup.controllers || "
                     "mount -t cgroup2 none /sys/fs/cgroup 2>&1").strip()
    if mnt:
        warn("rimontaggio di cgroup2 dentro %s non riuscito: %s" % (SERVER, mnt))
        warn("nginx non potrà entrare nel cgroup e il lato server resterà vuoto.")

    # Prova della configurazione PRIMA di avviare. Senza, l'errore di nginx
    # finisce nei tubi che Mininet apre per popen() e che nessuno legge: si
    # vedrebbe solo «non risponde», che non dice niente.
    test = server.cmd("nginx -t -c %s -p %s/ 2>&1" % (conf, prefix))
    if "successful" not in test:
        raise RuntimeError("nginx rifiuta la configurazione:\n%s"
                           % test.strip())

    # Il processo entra nel cgroup PRIMA di diventare nginx, così anche il
    # processo principale e i suoi lavoratori vi appartengono e i socket che
    # accettano ereditano l'associazione al cgroup.
    #
    # «exec 2>>log» PER PRIMO: la shell elabora le ridirezioni da sinistra a
    # destra, e se la scrittura in cgroup.procs fallisce l'errore va sullo
    # stderr in vigore in quel momento. Mandandolo nel registro prima di
    # tentare la scrittura, un fallimento resta leggibile invece di finire in
    # un tubo che nessuno legge.
    startlog = os.path.join(prefix, "avvio.log")
    cmd = ("exec 2>>%s; echo $$ > %s/cgroup.procs; "
           "exec nginx -c %s -p %s/ >>%s 2>&1"
           % (startlog, cgroup, conf, prefix, startlog))
    proc = server.popen(["sh", "-c", cmd])

    last = ""
    for _ in range(50):
        time.sleep(0.1)
        last = net.get(CLIENTS[0][0]).cmd(
            "curl -s -o /dev/null -m 2 -w '%%{http_code}' "
            "http://%s/%s" % (SERVER_IP, PROBE_NAME)).strip()
        if "200" in last:
            verifica_cgroup(cgroup, startlog)
            return proc

    # Diagnosi: che cosa ha risposto il client, che cosa ha detto nginx
    # all'avvio, e che cosa c'è nel suo registro degli errori.
    pieces = ["nginx non risponde.",
              "  codice HTTP ricevuto dal client: %s" % (last or "(nessuno)"),
              "  radice dei documenti: %s" % docroot]
    for name in ("avvio.log", "error.log"):
        f = os.path.join(prefix, name)
        if os.path.exists(f):
            body = open(f).read().strip()
            pieces.append("  --- %s ---\n%s" % (name, body or "(vuoto)"))
    if last.startswith("403"):
        pieces.append("  403 = nginx c'è ma non può leggere i file: controllare "
                      "i permessi di attraversamento sulla catena di cartelle "
                      "fino alla radice dei documenti.")
    if last.startswith("404"):
        pieces.append("  404 = nginx risponde ma non trova %s nella radice dei "
                      "documenti. Il file lo crea make_objects(): se manca, "
                      "la radice non è quella che si crede." % PROBE_NAME)
    if last in ("000", ""):
        pieces.append("  000 = nessuna connessione: nginx non si è avviato, "
                      "oppure non è in ascolto sulla porta %d." % HTTP_PORT)
    proc.kill()
    raise RuntimeError("\n".join(pieces))


# ===========================================================================
# Configurazione della politica sul server
# ===========================================================================

def apply_policy(net, policy, static_high):
    """Prepara h1 per la politica indicata. Restituisce il valore di initcwnd
    effettivamente impostato sulla route."""
    server = net.get(SERVER)
    spec = POLICIES[policy]

    initcwnd = spec["initcwnd"]
    if initcwnd is None:
        initcwnd = static_high

    # La route della sottorete locale è quella creata dal kernel insieme
    # all'indirizzo: va sostituita conservandone tutti gli attributi, perché
    # «ip route replace» senza di essi la riscriverebbe monca.
    server.cmd("ip route replace 10.0.0.0/24 dev %s-eth0 proto kernel "
               "scope link src %s initcwnd %d"
               % (SERVER, SERVER_IP, initcwnd))

    server.cmd("sysctl -q -w net.ipv4.tcp_no_metrics_save=%d"
               % (0 if spec["metrics"] else 1))
    # Azzeramento incondizionato: le iterazioni devono essere indipendenti,
    # anche per la configurazione che la cache la usa — impara da capo ogni
    # volta, come farebbe un server appena avviato.
    server.cmd("ip tcp_metrics flush all 2>/dev/null")
    return initcwnd


def start_loader(net, policy, run_id, csv_path, bw, obj_bytes_, iteration,
                 cgroup, iw_max, alpha_shift, retrans_thresh, logfile,
                 static_high=None):
    spec = POLICIES[policy]

    # Opzioni comuni a tutti e quattro i programmi.
    args = [policy_bin(policy),
            "--policy-label", policy,
            "--cgroup", cgroup,
            "--csv", csv_path,
            "--run-id", run_id,
            "--bw-mbit", str(bw),
            "--obj-bytes", str(obj_bytes_),
            "--iteration", str(iteration)]

    # Opzioni proprie della politica. Le si passano solo a chi le accetta: il
    # programma della politica 1 non ha saturazioni ne' media mobile, e
    # passargliele sarebbe rumore.
    subst = {"iw_min": IW_MIN, "iw_max": iw_max,
             "alpha": alpha_shift, "thresh": retrans_thresh,
             "crescita": CRESCITA_MAX,
             "static_high": static_high if static_high is not None else 0,
             # gli indirizzi dei client, per il precaricamento di iw_map
             "dst": ",".join(c[1] for c in CLIENTS)}
    args += [a.format(**subst) if "{" in a else a for a in spec["extra"]]
    server = net.get(SERVER)
    proc = server.popen(args, stdout=logfile, stderr=logfile)

    # Il caricatore scrive l'intestazione del CSV appena è agganciato: la
    # comparsa del file è il segnale che si può cominciare a interrogare.
    for _ in range(100):
        if os.path.exists(csv_path):
            time.sleep(0.15)
            return proc
        if proc.poll() is not None:
            raise RuntimeError("augmenter è terminato subito; vedere %s"
                               % logfile.name)
        time.sleep(0.05)
    proc.kill()
    raise RuntimeError("augmenter non è diventato pronto entro 5 s")


def stop_nginx(proc, cgroup):
    """Chiude nginx E i suoi lavoratori.

    `proc.kill()` manda SIGKILL al solo processo principale: i lavoratori
    diventano orfani, continuano a vivere e restano nel cgroup. È il motivo
    per cui il conteggio stampato da verifica_cgroup() cresceva di due a ogni
    banda — 9, poi 11, poi 13. Non falsa le misure, perché quei processi
    stanno in uno spazio dei nomi di rete ormai smontato e non possono più
    ricevere traffico, ma sporca il perimetro che il cgroup dovrebbe
    circoscrivere e rende illeggibile proprio il controllo che serve a
    verificarlo.

    SIGQUIT chiede a nginx la chiusura ordinata, che comprende i lavoratori.
    """
    if proc.poll() is None:
        proc.send_signal(signal.SIGQUIT)
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()

    # Rete di sicurezza per i lavoratori sopravvissuti a una corsa precedente.
    # Si colpiscono SOLO i processi che si chiamano nginx: nel cgroup non
    # dovrebbe esserci altro, ma il caricatore è lì accanto e non va toccato.
    try:
        with open(os.path.join(cgroup, "cgroup.procs")) as f:
            rimasti = [int(l) for l in f if l.strip()]
    except OSError:
        return
    for pid in rimasti:
        try:
            if open("/proc/%d/comm" % pid).read().strip() == "nginx":
                os.kill(pid, signal.SIGKILL)
        except OSError:
            pass


def stop_loader(proc):
    if proc.poll() is not None:
        return
    proc.send_signal(signal.SIGINT)
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()


# ===========================================================================
# Esecuzione di una cella
# ===========================================================================

CLIENT_HEADER = ("run_id,policy,bw_mbit,obj_label,obj_bytes,iteration,"
                 "client,client_ip,rtt_nominal_ms,round,local_port,http_code,"
                 "size_download,time_connect_s,time_starttransfer_s,"
                 "time_total_s,fct_s,goodput_mbps\n")

CURL_FMT = ("%{local_port},%{http_code},%{size_download},"
            "%{time_connect},%{time_starttransfer},%{time_total}")


def esegui_giri(net, label, rounds, run_id):
    """I giri di richieste, e nient'altro.

    I client interrogano IN SEQUENZA: h2, poi h3, poi h4, pausa, e si
    ricomincia. La sequenzialità è parte del protocollo — con richieste
    contemporanee i tre flussi si contenderebbero il collo di bottiglia e il
    tempo di completamento misurerebbe la contesa invece della finestra
    iniziale.

    Restituisce, per ogni client, il file grezzo con l'uscita di curl.
    """
    obj = object_name(label)
    tmp = {}
    for name, _ip, _d in CLIENTS:
        tmp[name] = "/tmp/aug_%s_%s.raw" % (run_id, name)
        if os.path.exists(tmp[name]):
            os.remove(tmp[name])

    for _r in range(1, rounds + 1):
        for name, _ip, _d in CLIENTS:
            h = net.get(name)
            h.cmd("curl -s -o /dev/null -m %d -w '%s\\n' http://%s/%s "
                  ">> %s 2>/dev/null"
                  % (CURL_TIMEOUT, CURL_FMT, SERVER_IP, obj, tmp[name]))
        time.sleep(ROUND_SLEEP)
    return tmp


def riversa_csv(tmp, client_csv, run_id, policy, bw, label, iteration):
    """Trasforma l'uscita grezza di curl nel CSV lato client, e cancella i
    file grezzi. Restituisce il numero di richieste registrate."""
    nbytes = object_bytes(label)
    n = 0
    with open(client_csv, "w") as out:
        out.write(CLIENT_HEADER)
        for name, ip, delay in CLIENTS:
            rtt_nom = 2 * delay
            if not os.path.exists(tmp[name]):
                continue
            with open(tmp[name]) as f:
                for i, line in enumerate(f, start=1):
                    line = line.strip()
                    if not line:
                        continue
                    parts = line.split(",")
                    if len(parts) != 6:
                        continue
                    lport, code, dl, t_conn, t_start, t_total = parts
                    try:
                        t_conn = float(t_conn)
                        t_start = float(t_start)
                        t_total = float(t_total)
                        dl_i = int(dl)
                    except ValueError:
                        continue
                    # Tempo di completamento del trasferimento: dal termine
                    # dell'apertura all'ultimo byte. L'apertura è esclusa
                    # perché è comune a tutte le politiche e ne diluirebbe
                    # le differenze; time_total resta comunque nel CSV.
                    fct = max(t_total - t_conn, 1e-9)
                    good = dl_i * 8.0 / fct / 1e6
                    out.write("%s,%s,%d,%s,%d,%d,%s,%s,%d,%d,%s,%s,%d,"
                              "%.6f,%.6f,%.6f,%.6f,%.4f\n"
                              % (run_id, policy, bw, label, nbytes, iteration,
                                 name, ip, rtt_nom, i, lport, code, dl_i,
                                 t_conn, t_start, t_total, fct, good))
                    n += 1
            os.remove(tmp[name])
    return n


def run_cell(net, policy, bw, label, iteration, rounds, outdir,
             static_high, alpha_shift, retrans_thresh, iw_max, logfile):
    """Una cella = una politica, una banda, una taglia, una iterazione."""
    nbytes = object_bytes(label)
    run_id = run_id_di(policy, bw, label, iteration)

    pdir = os.path.join(outdir, policy)
    os.makedirs(pdir, exist_ok=True)
    server_csv = os.path.join(pdir, "server_%s.csv" % run_id)
    client_csv = os.path.join(pdir, "client_%s.csv" % run_id)

    initcwnd = apply_policy(net, policy, static_high)
    cgroup = ensure_cgroup()

    proc = start_loader(net, policy, run_id, server_csv, bw, nbytes,
                        iteration, cgroup, iw_max, alpha_shift,
                        retrans_thresh, logfile, static_high)
    tmp = {}
    try:
        tmp = esegui_giri(net, label, rounds, run_id)
    finally:
        # Margine perché gli ultimi socket completino la chiusura e il
        # programma emetta i record corrispondenti prima che lo si fermi.
        time.sleep(0.5)
        stop_loader(proc)

    riversa_csv(tmp, client_csv, run_id, policy, bw, label, iteration)
    return client_csv, server_csv, initcwnd


def cell_done(outdir, policy, bw, label, iteration, rounds):
    run_id = run_id_di(policy, bw, label, iteration)
    pdir = os.path.join(outdir, policy)
    c = os.path.join(pdir, "client_%s.csv" % run_id)
    s = os.path.join(pdir, "server_%s.csv" % run_id)
    if not (os.path.exists(c) and os.path.exists(s)):
        return False
    with open(c) as f:
        righe_c = sum(1 for _ in f) - 1
    with open(s) as f:
        righe_s = sum(1 for _ in f) - 1
    atteso = rounds * len(CLIENTS)
    # Il lato server dev'esserci DAVVERO: il caricatore scrive l'intestazione
    # all'avvio, quindi "il file esiste" non significa "ha catturato qualcosa".
    # Senza questo controllo una cella muta conta come completa e --resume la
    # salta per sempre. La tolleranza del 10 per cento copre l'ultimo record
    # che puo' non essere uscito prima dell'arresto del caricatore.
    return righe_c >= atteso and righe_s >= 0.9 * atteso


# ===========================================================================
# Campagna
# ===========================================================================

def estimate_seconds(profile, rounds, iterations):
    total = 0.0
    for bw in profile["bandwidths"]:
        for label in profile["objects"]:
            n = object_bytes(label)
            # trasmissione + un paio di RTT di apertura e coda + costo del
            # processo curl
            per_req = n * 8.0 / (bw * 1e6) + 0.12
            total += (per_req * len(CLIENTS) + ROUND_SLEEP) * rounds \
                     * iterations * len(profile["policies"])
        # avvio e arresto del caricatore per cella
        total += 1.5 * len(profile["objects"]) * iterations \
                 * len(profile["policies"])
    return total


def cmd_run(args):
    profile = dict(PROFILES[args.profile])
    if args.bandwidths:
        profile["bandwidths"] = [int(x) for x in args.bandwidths.split(",")]
    if args.objects:
        profile["objects"] = args.objects.split(",")
    if args.policies:
        profile["policies"] = args.policies.split(",")
    iterations = args.iterations or profile["iterations"]
    rounds = args.rounds or profile["rounds"]

    # Si eseguono solo le politiche il cui programma è stato compilato: così
    # si può cominciare con la prima e aggiungere le altre man mano, senza che
    # la campagna si fermi a metà su un binario che non c'è.
    # --- ARRESTO 1: binari mancanti ---------------------------------------
    # Prima era un avviso e la campagna proseguiva sulle politiche rimaste.
    # Ma l'avviso scorre via nei primi secondi, e sei ore dopo ci si ritrova
    # con i soli riferimenti e nessun dato sulle politiche adattive, cioè su
    # ciò che la tesi deve dimostrare. Saltarle dev'essere una scelta
    # dichiarata, non il comportamento predefinito.
    mancanti = [p for p in profile["policies"] if not policy_available(p)]
    if mancanti:
        for p in mancanti:
            warn("politica «%s»: manca %s" % (p, policy_bin(p)))
        if not args.salta_mancanti:
            sys.exit(
                "\nMancano %d politiche su %d richieste. Una campagna lanciata\n"
                "così girerebbe per ore senza produrre i dati che servono.\n\n"
                "  make -C %s\n"
                "      compila le politiche presenti nella cartella\n"
                "  ... run --policies %s\n"
                "      dichiara esplicitamente quali misurare\n"
                "  ... run --salta-mancanti\n"
                "      procedi lo stesso, saltando quelle assenti\n"
                % (len(mancanti), len(profile["policies"]), AUG_DIR,
                   ",".join(p for p in profile["policies"]
                            if policy_available(p)) or "<elenco>"))
        profile["policies"] = [p for p in profile["policies"]
                               if policy_available(p)]
    if not profile["policies"]:
        sys.exit("Nessuna politica eseguibile. Compilare almeno un programma "
                 "nella cartella %s, oppure indicarne un'altra con --aug-dir."
                 % AUG_DIR)

    # --- ARRESTO 2: finestra statica alta non tarata -----------------------
    # Serve solo alla configurazione «statichigh»: se non è in programma, il
    # valore è irrilevante e non si disturba nessuno.
    static_high = args.static_high or load_static_high(args.outdir)
    # Serve a chi prende la finestra dalla route (initcwnd None) e a chi la
    # riceve come opzione ({static_high} fra le sue extra).
    vogliono_taratura = [
        p for p in profile["policies"]
        if POLICIES[p]["initcwnd"] is None
        or any("{static_high}" in a for a in POLICIES[p]["extra"])]
    if static_high is None and vogliono_taratura:
        sys.exit(
            "\nLe configurazioni %s vogliono una finestra tarata sul\n"
            % ", ".join("«%s»" % p for p in vogliono_taratura) +
            "banco, e in %s non c'è calibration.json.\n\n"
            "  sudo python3 %s calibrate\n"
            "      taratura, circa venti minuti\n"
            "  ... run --static-high N\n"
            "      impone un valore scelto a mano, da dichiarare in tesi\n"
            "  ... run --policies %s\n"
            "      misura le altre configurazioni e rimanda queste\n"
            % (os.path.abspath(args.outdir), os.path.abspath(__file__),
               ",".join(p for p in profile["policies"]
                        if p not in vogliono_taratura) or "<elenco>"))

    outdir = args.outdir
    os.makedirs(outdir, exist_ok=True)
    docroot = make_objects(os.path.join(outdir, "_docroot"), profile["objects"])
    prefix = os.path.join(outdir, "_nginx")

    n_cells = (len(profile["bandwidths"]) * len(profile["objects"])
               * len(profile["policies"]) * iterations)
    est = estimate_seconds(profile, rounds, iterations)

    say("Campagna «%s»" % args.profile)
    note("bande        : %s Mbit/s" % ", ".join(map(str, profile["bandwidths"])))
    note("oggetti      : %s" % ", ".join(profile["objects"]))
    note("politiche    : %s" % ", ".join(profile["policies"]))
    note("iterazioni   : %d   giri per iterazione: %d   client: %d"
         % (iterations, rounds, len(CLIENTS)))
    note("celle        : %d   connessioni totali: %d"
         % (n_cells, n_cells * rounds * len(CLIENTS)))
    note("finestra statica alta: %s"
         % ("%d segmenti" % static_high if static_high is not None
            else "non serve (statichigh non è in programma)"))
    note("durata stimata: %s" % human_time(est))
    note("risultati in : %s" % os.path.abspath(outdir))
    print()

    if args.dry_run:
        return

    logpath = os.path.join(outdir, "campagna.log")
    logfile = open(logpath, "a")
    logfile.write("\n===== avvio %s =====\n" % time.strftime("%F %T"))
    logfile.flush()

    t0 = time.time()
    done = 0
    skipped = 0

    for bw in profile["bandwidths"]:
        iw_max = iw_max_for(bw, args.iw_max_ceiling)
        say("Banda %d Mbit/s — coda %d pacchetti — saturazione superiore %d segmenti"
            % (bw, BOTTLENECK_QUEUE, iw_max))

        mn_cleanup()
        net = build_net(bw)
        nginx = None
        try:
            nginx = start_nginx(net, docroot, prefix, ensure_cgroup())

            # Ordine dei cicli: iterazione all'esterno delle politiche. Le
            # dieci ripetizioni di politiche diverse cadono così a pochi
            # minuti l'una dall'altra e una deriva lenta dello stato della
            # macchina si distribuisce equamente, invece di favorire la
            # politica che è stata misurata nell'ora migliore.
            for it in range(1, iterations + 1):
                for policy in profile["policies"]:
                    for label in profile["objects"]:
                        if args.resume and cell_done(outdir, policy, bw,
                                                     label, it, rounds):
                            skipped += 1
                            done += 1
                            continue
                        t = time.time()
                        try:
                            _c, _s, icw = run_cell(
                                net, policy, bw, label, it, rounds, outdir,
                                static_high, args.alpha_shift,
                                args.retrans_thresh, iw_max, logfile)
                        except Exception as e:      # noqa: BLE001
                            warn("cella %s bw%d %s it%02d fallita: %s"
                                 % (policy, bw, label, it, e))
                            logfile.write("FALLITA %s bw%d %s it%02d: %r\n"
                                          % (policy, bw, label, it, e))
                            logfile.flush()
                            continue
                        done += 1
                        elapsed = time.time() - t0
                        remaining = (elapsed / done * (n_cells - done)
                                     if done else 0)
                        print("    [%4d/%4d] %-11s bw%-5d %-5s it%02d  "
                              "initcwnd=%-4d  %5.1fs   resta %s"
                              % (done, n_cells, policy, bw, label, it, icw,
                                 time.time() - t, human_time(remaining)),
                              flush=True)
        finally:
            if nginx:
                stop_nginx(nginx, ensure_cgroup())
            net.stop()

    logfile.close()
    say("Fatta in %s (%d celle, %d già presenti e saltate)"
        % (human_time(time.time() - t0), done, skipped))
    note("Analisi:  python3 %s %s" %
         (os.path.join(ROOT, "analysis", "stats.py"), os.path.abspath(outdir)))


# ===========================================================================
# check
# ===========================================================================

def cmd_check(args):
    say("Verifica dell'ambiente")
    note("cartella dei programmi: %s" % AUG_DIR)
    for pol in POLICY_ORDER:
        b = policy_bin(pol)
        if policy_available(pol):
            note("  %-11s %s" % (pol, b))
        else:
            warn("%-11s ASSENTE (%s)" % (pol, b))
    if not any(policy_available(p) for p in POLICY_ORDER):
        warn("nessun programma compilato: fare «make» nella cartella politiche")
    for tool in ("nginx", "curl", "iperf3", "ethtool", "ovs-vsctl"):
        note("%-10s : %s" % (tool, shutil.which(tool) or "ASSENTE"))

    say("Parametri derivati per cella")
    print("    %-8s %-8s %-10s %-10s %-10s %s"
          % ("banda", "coda", "BDP h2", "BDP h3", "BDP h4", "sat. sup."))
    for bw in BANDWIDTHS:
        bdps = []
        for _n, _ip, d in CLIENTS:
            bdps.append(bdp_segments(bw, 2 * d))
        print("    %-8s %-8s %-10.0f %-10.0f %-10.0f %d"
              % ("%d Mb" % bw, "%d pkt" % BOTTLENECK_QUEUE,
                 bdps[0], bdps[1], bdps[2], iw_max_for(bw)))
    print()
    note("BDP in segmenti da %d byte, calcolato sul RTT nominale (senza coda)."
         % MSS)
    note("La saturazione superiore usa il RTT più alto e vi somma la coda,")
    note("con tetto assoluto %d segmenti." % IW_MAX_CEILING)

    say("Prova della topologia a %d Mbit/s" % BANDWIDTHS[1])
    mn_cleanup()
    net = build_net(BANDWIDTHS[1])
    try:
        for name, _ip, delay in CLIENTS:
            out = net.get(name).cmd("ping -c 5 -q %s" % SERVER_IP)
            m = re.search(r"=\s*([\d.]+)/([\d.]+)/([\d.]+)", out)
            got = float(m.group(2)) if m else float("nan")
            print("    %s  RTT nominale %2d ms   misurato %6.2f ms"
                  % (name, 2 * delay, got))

        # Verifica che la coda sia DOVE la vuole il protocollo: venti pacchetti
        # su s1 verso s2, e nessun limitatore sull'uscita del server, che
        # altrimenti accoderebbe al posto suo.
        print()
        out_h1 = net.get(SERVER).cmd("tc qdisc show dev %s-eth0" % SERVER)
        out_s1 = net.get("s1").cmd("tc qdisc show dev s1-eth2")
        print("    uscita del server (%s-eth0): %s"
              % (SERVER, " | ".join(l.strip() for l in out_h1.splitlines() if l.strip())))
        print("    collo di bottiglia (s1-eth2): %s"
              % " | ".join(l.strip() for l in out_s1.splitlines() if l.strip()))
        if "htb" in out_h1 or "netem" in out_h1:
            warn("l'uscita del server ha un limitatore: la coda potrebbe "
                 "formarsi là invece che sul collo di bottiglia")
        if "limit %d" % BOTTLENECK_QUEUE in out_s1:
            note("coda di %d pacchetti confermata su s1 verso s2"
                 % BOTTLENECK_QUEUE)
        else:
            warn("non trovo «netem limit %d» su s1-eth2" % BOTTLENECK_QUEUE)
        print()

        docroot = make_objects(os.path.join(args.outdir, "_docroot"),
                               [o[0] for o in OBJECTS])
        nginx = start_nginx(net, docroot,
                            os.path.join(args.outdir, "_nginx"),
                            ensure_cgroup())
        note("nginx risponde")
        for label in ("1K", "200K", "10M"):
            out = net.get("h4").cmd(
                "curl -s -o /dev/null -w '%%{time_total} %%{size_download}' "
                "http://%s/%s" % (SERVER_IP, object_name(label)))
            print("    scarico %-5s : %s" % (label, out.strip()))
        stop_nginx(nginx, ensure_cgroup())
    finally:
        net.stop()
    say("Verifica conclusa")


def cmd_shell(args):
    mn_cleanup()
    net = build_net(args.bw)
    docroot = make_objects(os.path.join(args.outdir, "_docroot"),
                           [o[0] for o in OBJECTS])
    nginx = start_nginx(net, docroot, os.path.join(args.outdir, "_nginx"),
                        ensure_cgroup())
    say("Topologia attiva a %d Mbit/s. nginx serve %s su h1." % (args.bw, docroot))
    note("Esempio:  h4 curl -s -o /dev/null -w '%%{time_total}\\n' "
         "http://%s/obj_200K.bin" % SERVER_IP)
    note("Il caricatore NON è avviato: lanciarlo a mano da un altro terminale.")
    try:
        CLI(net)
    finally:
        stop_nginx(nginx, ensure_cgroup())
        net.stop()


# ===========================================================================
# traffico — il giro corto, un esperimento alla volta
# ===========================================================================

def cgroup_ha_programma(cgroup):
    """True se al cgroup è agganciato almeno un programma sockops, False se
    non ce n'è nessuno, None se non si riesce a stabilirlo (bpftool assente).

    Serve a intercettare l'errore più facile da fare con il giro corto:
    lanciare il traffico senza aver avviato il caricatore nell'altro
    terminale. Senza questo controllo si otterrebbe un CSV lato client pieno
    e nessun CSV lato server, e ci si accorgerebbe del guasto solo in fase di
    analisi.
    """
    try:
        out = subprocess.run(["bpftool", "cgroup", "show", cgroup],
                             capture_output=True, text=True,
                             timeout=5).stdout
    except Exception:       # noqa: BLE001
        return None
    return "sock_ops" in out


def cmd_traffico(args):
    """Costruisce la topologia, esegue lo scambio di pacchetti, scrive il CSV
    lato client, smonta tutto.

    Il caricatore NON viene avviato da qui: lo si avvia a mano in un altro
    terminale, prima di lanciare questo comando, e lo si ferma dopo. È il modo
    di eseguire UN esperimento e guardare che cosa succede; «run» fa la stessa
    cosa ripetuta sulla griglia intera, senza nessuno alla tastiera.

    Funziona perché il programma si aggancia a un CGROUP, che è una struttura
    di tutta la macchina e non dello spazio dei nomi di rete: il caricatore
    può quindi esistere prima della topologia, e nginx — che Mininet avvia
    dentro h1 ma dentro quello stesso cgroup — ricade sotto il programma
    ugualmente.
    """
    labels = [x.strip() for x in args.obj.split(",") if x.strip()]
    disponibili = dict(OBJECTS)
    for lab in labels:
        if lab not in disponibili:
            sys.exit("Taglia sconosciuta «%s». Disponibili: %s"
                     % (lab, ", ".join(o[0] for o in OBJECTS)))

    outdir = args.outdir
    os.makedirs(outdir, exist_ok=True)
    docroot = make_objects(os.path.join(outdir, "_docroot"), labels)
    prefix = os.path.join(outdir, "_nginx")
    mandir = os.path.join(outdir, "manuale")
    os.makedirs(mandir, exist_ok=True)
    cgroup = ensure_cgroup()

    # --- il caricatore c'è? ---
    stato = cgroup_ha_programma(cgroup)
    if stato is False:
        warn("a %s non è agganciato nessun programma sockops." % cgroup)
        note("")
        note("Il caricatore va avviato PRIMA, in un altro terminale:")
        note("")
        rid = run_id_di(args.tag, args.bw, labels[0], args.iteration)
        note("  sudo mkdir -p %s" % cgroup)
        note("  sudo %s \\" % os.path.join(AUG_DIR, "static10", "augmenter"))
        note("       --cgroup %s \\" % cgroup)
        note("       --csv %s \\" % os.path.join(mandir, "server_%s.csv" % rid))
        note("       --policy-label %s --run-id %s \\" % (args.tag, rid))
        note("       --bw-mbit %d --obj-bytes %d --iteration %d"
             % (args.bw, disponibili[labels[0]], args.iteration))
        note("")
        note("Poi rilancia questo comando. Per procedere lo stesso: --forza")
        if not args.forza:
            sys.exit(1)
    elif stato is None:
        warn("bpftool non disponibile: non posso verificare che il caricatore "
             "sia agganciato. Controlla tu.")
    else:
        note("caricatore agganciato a %s" % cgroup)

    say("Giro corto — banda %d Mbit/s, coda %d pacchetti, initcwnd %d sulla route"
        % (args.bw, BOTTLENECK_QUEUE, args.initcwnd))
    note("oggetti  : %s" % ", ".join(labels))
    note("giri     : %d  ×  %d client  =  %d connessioni per oggetto"
         % (args.rounds, len(CLIENTS), args.rounds * len(CLIENTS)))
    note("risultati: %s" % os.path.abspath(mandir))
    note("")
    note("stats.py appaia i due lati PER NOME DI FILE. Il CSV del caricatore")
    note("(--csv) deve quindi chiamarsi esattamente:")
    for label in labels:
        note("  server_%s.csv"
             % run_id_di(args.tag, args.bw, label, args.iteration))
    print()

    mn_cleanup()
    net = build_net(args.bw)
    nginx = None
    try:
        nginx = start_nginx(net, docroot, prefix, cgroup)
        server = net.get(SERVER)

        # Stessa preparazione che «run» fa per ogni cella, ma con i valori
        # scelti a mano invece che dalla tabella delle politiche.
        server.cmd("ip route replace 10.0.0.0/24 dev %s-eth0 proto kernel "
                   "scope link src %s initcwnd %d"
                   % (SERVER, SERVER_IP, args.initcwnd))
        server.cmd("sysctl -q -w net.ipv4.tcp_no_metrics_save=%d"
                   % (0 if args.metrics else 1))
        server.cmd("ip tcp_metrics flush all 2>/dev/null")

        for label in labels:
            run_id = run_id_di(args.tag, args.bw, label, args.iteration)
            client_csv = os.path.join(mandir, "client_%s.csv" % run_id)
            t = time.time()
            tmp = esegui_giri(net, label, args.rounds, run_id)
            # Margine perché gli ultimi socket si chiudano e il caricatore
            # emetta i record corrispondenti: qui non possiamo fermarlo noi,
            # ma i record devono comunque essere usciti.
            time.sleep(0.5)
            n = riversa_csv(tmp, client_csv, run_id, args.tag, args.bw,
                            label, args.iteration)
            print("    %-5s  %3d richieste  %5.1f s   -> %s"
                  % (label, n, time.time() - t, client_csv), flush=True)
    finally:
        if nginx:
            stop_nginx(nginx, cgroup)
        net.stop()

    # Il lato server esiste? Il caricatore crea il file all'avvio, quindi a
    # questo punto ci dev'essere, ancora aperto. Se manca, l'analisi dirà
    # «nessuna connessione ricostruita» e la causa — un nome diverso passato a
    # --csv — sarebbe tutt'altro che evidente. Meglio dirlo adesso.
    mancanti = [run_id_di(args.tag, args.bw, l, args.iteration) for l in labels
                if not os.path.exists(
                    os.path.join(mandir, "server_%s.csv"
                                 % run_id_di(args.tag, args.bw, l, args.iteration)))]
    if mancanti:
        print()
        warn("manca il CSV lato server per: %s" % ", ".join(mancanti))
        warn("Il caricatore sta scrivendo su un altro nome, e i due lati non si")
        warn("congiungeranno. Rinomina il suo file in server_<run_id>.csv, oppure")
        warn("rilancialo con --csv giusto e ripeti il giro.")

    print()
    say("Fatto. Adesso, nell'altro terminale, ferma il caricatore con Ctrl-C:")
    note("è lui che chiude e completa il CSV lato server.")
    note("Poi:  python3 %s %s"
         % (os.path.join(ROOT, "analysis", "stats.py"), os.path.abspath(outdir)))


# ===========================================================================
# calibrate
# ===========================================================================

def load_static_high(outdir):
    """La finestra statica alta tarata sul banco, o None se non lo è.

    Restituire un valore di ripiego sarebbe peggio che non restituirne: la
    campagna girerebbe per ore producendo una colonna «statichigh» che non
    significa niente, e l'avviso di ripiego sarebbe scorso via nei primi
    secondi. Chi chiama decide che cosa fare del None; cmd_run si ferma.
    """
    path = os.path.join(outdir, "calibration.json")
    if not os.path.exists(path):
        return None
    try:
        with open(path) as f:
            return int(json.load(f)["static_high_iw"])
    except Exception as e:      # noqa: BLE001
        warn("calibration.json presente ma illeggibile (%s): %s" % (e, path))
        return None


def conta_retrans(scsv, obj_bytes_, per_dst):
    """Accumula in per_dst {ip: [flussi, flussi con ritrasmissioni]} leggendo
    il CSV del caricatore.

    Scarta le righe troppo corte per essere il trasferimento dell'oggetto: la
    richiesta di probe.bin con cui start_nginx accerta che il server risponda
    passa per lo stesso cgroup e viene registrata come tutte le altre. È un
    trasferimento da pochi byte, non fa crescere nessuna finestra, e lasciarlo
    dentro falserebbe il conteggio del solo client che lo emette — sempre lo
    stesso, CLIENTS[0].
    """
    i_dst   = CSV_SERVER_COLS.index("dst_ip")
    i_retr  = CSV_SERVER_COLS.index("retrans")
    i_bytes = CSV_SERVER_COLS.index("bytes_acked")
    minimo  = obj_bytes_ // 2

    with open(scsv) as f:
        for line in f.read().splitlines()[1:]:
            r = line.split(",")
            if len(r) != len(CSV_SERVER_COLS):
                continue
            try:
                if int(r[i_bytes]) < minimo:
                    continue
                voce = per_dst.setdefault(r[i_dst], [0, 0])
                voce[0] += 1
                if int(r[i_retr]) > 0:
                    voce[1] += 1
            except ValueError:
                continue


def quota_peggiore(per_dst):
    """(quota del client peggiore, descrizione), oppure (None, ...) se non è
    stata letta nemmeno una riga.

    Due scelte, entrambe correzioni di difetti trovati misurando.

    Il None è deliberato. La versione precedente restituiva 0.0 quando non
    c'erano dati, e il criterio di scelta lo leggeva come «non ritrasmette
    mai»: l'assenza di misura diventava il punteggio migliore possibile, e la
    finestra più grande vinceva proprio quando la misura era fallita.

    Il massimo, e non la media, perché sul banco perde soltanto il client più
    vicino: mediare i tre divide per tre la sola quota che conta, e mediare
    anche le taglie la divide di nuovo. Una quota reale del 33 % usciva
    stampata come 15 %. La specifica chiede le metriche separate per
    destinazione, e il criterio deve rispettarla: «finestra alta ma adeguata
    alla rete» significa adeguata anche al percorso più corto.
    """
    quote = {ip: v[1] / v[0] for ip, v in per_dst.items() if v[0]}
    if not quote:
        return None, "nessuna misura"
    peggiore = max(quote, key=lambda k: quote[k])
    return quote[peggiore], "%s %d/%d" % (peggiore, per_dst[peggiore][1],
                                          per_dst[peggiore][0])


def valuta_candidati(validi, quote_base, max_retrans_rate, tolleranza):
    """Decide quali finestre sono ammissibili, confrontando la quota di flussi
    con ritrasmissioni COPPIA PER COPPIA (taglia, client) con la linea di base.

    Restituisce (ammessi, varia):
      ammessi  sottoinsieme di `validi` che non peggiora nessuna coppia;
      varia    False se le ritrasmissioni sono identiche per ogni candidato —
               nel qual caso il criterio sulle perdite non sta discriminando e
               a scegliere resta il solo tempo di completamento.

    Perché coppia per coppia e non su un aggregato. Un limite assoluto
    presuppone che con la finestra predefinita non si perda niente, e sul banco
    non è vero: a 100 Mbit/s la coda da venti pacchetti è il 4 % del prodotto
    banda-ritardo, e il client vicino perde su TUTTI i flussi da 200 KB già con
    IW 10. La domanda giusta non è «quanto si perde» ma «si perde PIÙ di
    prima».

    Aggregando, però, anche quella domanda perde di senso: con una taglia che
    perde sempre e una che non perde mai la quota aggregata resta inchiodata al
    50 % per ogni candidato — sembra una misura ed è la media fra un caso rotto
    e uno sano. Coppia per coppia, la taglia sana conserva la sua sensibilità
    (lì la soglia vale max_retrans_rate e un peggioramento si vede) mentre
    quella rotta si limita a non poter peggiorare oltre il suo 100 %.
    """
    def soglia_di(coppia):
        return max(max_retrans_rate, quote_base.get(coppia, 0.0) + tolleranza)

    ammessi = {iw: v for iw, v in validi.items()
               if all(r <= soglia_di(k) for k, r in v[1].items())}

    varia = any(len({round(v[1].get(k, 0.0), 3) for v in validi.values()}) > 1
                for k in quote_base)
    return ammessi, varia


def cmd_calibrate(args):
    # La taratura misura le ritrasmissioni, e quelle le legge dal CSV lato
    # server: senza il programma di osservazione il criterio di scelta
    # perderebbe metà dei suoi termini e la raccomandazione sarebbe basata sul
    # solo tempo di completamento, cioè sul valore più alto sempre.
    if not policy_available("static10"):
        sys.exit("La taratura ha bisogno del programma di osservazione: manca "
                 "%s.\nCompilarlo con «make -C %s»."
                 % (policy_bin("static10"), AUG_DIR))

    outdir = args.outdir
    os.makedirs(outdir, exist_ok=True)
    result = {"date": time.strftime("%F %T"), "iperf3": {}, "rtt": {},
              "sweep": {}}

    docroot = make_objects(os.path.join(outdir, "_docroot"),
                           [o[0] for o in OBJECTS])
    prefix = os.path.join(outdir, "_nginx")

    # --- 1. banda effettivamente raggiungibile -----------------------------
    say("1/3  Banda raggiungibile (iperf3, 8 s per punto)")
    for bw in BANDWIDTHS:
        mn_cleanup()
        net = build_net(bw)
        try:
            srv = net.get(SERVER)
            srv.popen(["iperf3", "-s", "-1", "-p", "5201"])
            time.sleep(0.6)
            out = net.get("h2").cmd(
                "iperf3 -c %s -p 5201 -t 8 -J 2>/dev/null" % SERVER_IP)
            try:
                j = json.loads(out[out.index("{"):out.rindex("}") + 1])
                got = j["end"]["sum_received"]["bits_per_second"] / 1e6
            except Exception:       # noqa: BLE001
                got = float("nan")
            result["iperf3"]["%d" % bw] = round(got, 2)
            flag = "" if got > 0.85 * bw else "   <-- il banco non regge"
            print("    nominale %5d Mbit/s   misurato %8.1f Mbit/s%s"
                  % (bw, got, flag))

            for name, _ip, delay in CLIENTS:
                o = net.get(name).cmd("ping -c 10 -q %s" % SERVER_IP)
                m = re.search(r"=\s*([\d.]+)/([\d.]+)/([\d.]+)", o)
                if m:
                    result["rtt"].setdefault("%d" % bw, {})[name] = \
                        float(m.group(2))
        finally:
            net.stop()

    # --- 2. esplorazione della finestra statica ----------------------------
    sweep_bw = args.sweep_bw
    candidates = [int(x) for x in args.sweep_values.split(",")]
    labels = args.sweep_objects.split(",")
    say("2/3  Finestra statica alta: %d valori × %d taglie a %d Mbit/s"
        % (len(candidates), len(labels), sweep_bw))

    mn_cleanup()
    net = build_net(sweep_bw)
    logfile = open(os.path.join(outdir, "calibrazione.log"), "a")
    scores = {}
    try:
        nginx = start_nginx(net, docroot, prefix, ensure_cgroup())
        server = net.get(SERVER)
        for iw in candidates:
            fcts = []
            # Conteggio PER DESTINAZIONE, accumulato su tutte le taglie.
            # Il conteggio va tenuto per COPPIA (taglia, client), non
            # aggregato. Sul banco la degenerazione si vede solo così: a
            # 100 Mbit/s il client vicino perde su TUTTI i flussi da 200 KB e su
            # NESSUNO da 30 KB, e questo qualunque sia la finestra iniziale.
            # Aggregando, la quota esce ferma al 50 % per ogni candidato — un
            # numero che sembra una misura e invece è la media fra un caso
            # sempre rotto e uno sempre sano, e non discrimina niente.
            per_coppia = {}       # (taglia, ip) -> [flussi, con ritrasmissioni]
            for label in labels:
                server.cmd("ip route replace 10.0.0.0/24 dev %s-eth0 "
                           "proto kernel scope link src %s initcwnd %d"
                           % (SERVER, SERVER_IP, iw))
                server.cmd("sysctl -q -w net.ipv4.tcp_no_metrics_save=1")
                server.cmd("ip tcp_metrics flush all 2>/dev/null")

                cdir = os.path.join(outdir, "_calib")
                os.makedirs(cdir, exist_ok=True)
                run_id = "calib_iw%03d_%s" % (iw, label)
                scsv = os.path.join(cdir, "server_%s.csv" % run_id)
                proc = start_loader(net, "static10", run_id, scsv, sweep_bw,
                                    object_bytes(label), 0, ensure_cgroup(),
                                    iw_max_for(sweep_bw), args.alpha_shift,
                                    args.retrans_thresh, logfile)
                raws = {}
                try:
                    for n, _ip, _d in CLIENTS:
                        raws[n] = "/tmp/aug_%s_%s.raw" % (run_id, n)
                        if os.path.exists(raws[n]):
                            os.remove(raws[n])
                    for _r in range(args.sweep_rounds):
                        for n, _ip, _d in CLIENTS:
                            net.get(n).cmd(
                                "curl -s -o /dev/null -m %d -w '%s\\n' "
                                "http://%s/%s >> %s 2>/dev/null"
                                % (CURL_TIMEOUT, CURL_FMT, SERVER_IP,
                                   object_name(label), raws[n]))
                        time.sleep(ROUND_SLEEP)
                finally:
                    time.sleep(0.4)
                    stop_loader(proc)

                for n in raws:
                    if not os.path.exists(raws[n]):
                        continue
                    with open(raws[n]) as f:
                        for line in f:
                            p = line.strip().split(",")
                            if len(p) == 6 and p[1] == "200":
                                fcts.append(float(p[5]) - float(p[3]))
                    os.remove(raws[n])
                if os.path.exists(scsv):
                    d = {}
                    conta_retrans(scsv, object_bytes(label), d)
                    for ip, v in d.items():
                        per_coppia[(label, ip)] = v

            med = statistics.median(fcts) if fcts else float("nan")
            quote = {k: v[1] / v[0] for k, v in per_coppia.items() if v[0]}
            totale = sum(v[0] for v in per_coppia.values())
            scores[iw] = (med, quote, per_coppia, totale)
            if not quote:
                warn("IW %4d   FCT mediano %7.1f ms   RITRASMISSIONI NON "
                     "MISURATE (nessuna riga lato server)" % (iw, med * 1000))
            else:
                peggiore = max(quote, key=lambda k: quote[k])
                print("    IW %4d   FCT mediano %7.1f ms   su %d flussi   "
                      "coppia peggiore %s/%s  %d/%d"
                      % (iw, med * 1000, totale, peggiore[0], peggiore[1],
                         per_coppia[peggiore][1], per_coppia[peggiore][0]))
        stop_nginx(nginx, ensure_cgroup())
    finally:
        logfile.close()
        net.stop()

    # --- 3. raccomandazione ------------------------------------------------
    say("3/3  Raccomandazione")
    validi = {iw: v for iw, v in scores.items() if not math.isnan(v[0])}
    if not validi:
        sys.exit("Nessuna misura utilizzabile: la taratura non ha prodotto "
                 "nemmeno un tempo di completamento. Controllare "
                 "calibrazione.log.")

    # Arresto duro, non ripiego. Un valore di cui non conosciamo le
    # ritrasmissioni non è un candidato con un punteggio brutto: è un candidato
    # su cui non sappiamo niente, e proseguire vorrebbe dire sceglierne un
    # altro sulla base di un confronto incompleto.
    ciechi = [iw for iw, v in scores.items() if not v[1]]
    if ciechi:
        sys.exit("Per %s non è stata letta nemmeno una riga lato server: le\n"
                 "ritrasmissioni sono ignote e la raccomandazione sarebbe\n"
                 "basata sul solo tempo di completamento, cioè sul valore più\n"
                 "alto sempre. Controllare calibrazione.log e %s."
                 % (", ".join("IW %d" % i for i in ciechi),
                    os.path.join(outdir, "_calib")))

    # Il confronto con la linea di base si fa COPPIA PER COPPIA (taglia,
    # client), non su un aggregato, e la ragione è che l'aggregato mente.
    #
    # Un limite assoluto sulle ritrasmissioni presuppone che con la finestra
    # predefinita non si perda niente, e sul banco non è vero: a 100 Mbit/s la
    # coda da venti pacchetti è il 4 % del prodotto banda-ritardo, e il client
    # vicino perde su TUTTI i flussi da 200 KB già con IW 10. La domanda giusta
    # non è «quanto si perde» ma «si perde PIÙ di prima».
    #
    # Aggregando però anche quella domanda perde di senso. Con una taglia che
    # perde sempre e una che non perde mai, la quota aggregata resta inchiodata
    # al 50 % per ogni candidato: sembra una misura, ed è la media fra un caso
    # rotto e uno sano. Confrontando coppia per coppia, invece, la taglia sana
    # conserva la sua sensibilità — lì la soglia vale 0,05 e un peggioramento si
    # vede — mentre quella rotta si limita a non poter peggiorare oltre il suo
    # 100 %, che è la verità.
    iw_base = min(validi)
    quote_base = validi[iw_base][1]
    ammessi, varia = valuta_candidati(validi, quote_base,
                                      args.max_retrans_rate, args.tolleranza)

    note("linea di base: IW %d" % iw_base)
    note("soglia per coppia: quota della linea di base + %.1f punti, "
         "mai sotto il %.0f %%"
         % (args.tolleranza * 100, args.max_retrans_rate * 100))
    print()

    # Riepilogo per coppia: è quello che rende visibile se il criterio sta
    # discriminando o se è degenerato.
    coppie = sorted(quote_base)
    print("    %-6s %13s %8s  %s" % ("IW", "FCT mediano", "esito",
          "  ".join("%s/%s" % (t, ip.split(".")[-1]) for t, ip in coppie)))
    for iw in sorted(validi):
        fct, quote, per_coppia, tot = validi[iw]
        celle = "  ".join("%*s" % (len("%s/%s" % (t, ip.split(".")[-1])),
                                   "%d/%d" % (per_coppia.get((t, ip), [0, 0])[1],
                                              per_coppia.get((t, ip), [0, 0])[0]))
                          for t, ip in coppie)
        print("    %-6d %10.1f ms %8s  %s"
              % (iw, fct * 1000, "ammesso" if iw in ammessi else "scartato",
                 celle))
    print()

    # Se nessuna coppia distingue fra i candidati, il criterio sulle perdite non
    # sta scegliendo niente e a decidere è il solo tempo. Va detto, perché
    # cambia che cosa si può scrivere in tesi accanto al numero.
    if not varia:
        warn("le ritrasmissioni sono IDENTICHE per ogni finestra provata: su "
             "questo banco")
        warn("non dipendono dalla finestra iniziale, quindi il criterio sulle "
             "perdite non")
        warn("discrimina e a scegliere è il solo tempo di completamento. Da "
             "dichiarare in tesi.")
        print()

    if ammessi:
        best = min(ammessi, key=lambda k: ammessi[k][0])
        note("valore proposto: %d segmenti" % best)
        note("criterio: tempo di completamento mediano minimo fra i valori che")
        note("non peggiorano le ritrasmissioni di NESSUNA coppia (taglia, client).")
        if best == iw_base:
            warn("il migliore è la linea di base: allargare l'esplorazione con "
                 "--sweep-values, oppure la finestra alta non conviene su "
                 "questo banco.")
    else:
        best = iw_base
        warn("nessun valore batte la linea di base senza peggiorare le "
             "ritrasmissioni; ripiego su %d, cioè su di lei." % best)
    result["static_high_iw"] = best
    result["sweep"] = {
        str(k): {"fct_median_s": v[0],
                 "flows": v[3],
                 # una voce per coppia (taglia, client): «30K/10.0.0.2»
                 "retrans_per_coppia": {"%s/%s" % kk: "%d/%d" % (vv[1], vv[0])
                                        for kk, vv in sorted(v[2].items())}}
        for k, v in scores.items()}
    result["sweep_criterio"] = ("confronto con la linea di base coppia per "
                                "coppia (taglia, client), non su un aggregato")
    path = os.path.join(outdir, "calibration.json")
    with open(path, "w") as f:
        json.dump(result, f, indent=2)
    note("scritto %s" % path)


CSV_SERVER_COLS = [
    "run_id", "policy", "bw_mbit", "obj_bytes", "iteration",
    "dst_ip", "dport", "sport",
    "iw_route", "iw_applied", "max_cwnd", "srtt_us", "min_rtt_us", "retrans",
    "bytes_acked", "mss", "duration_us",
    "ewma_after", "samples", "penalties",
]


# ===========================================================================
# CLI
# ===========================================================================

def restituisci_proprieta(path):
    """Rende i risultati all'utente che ha invocato sudo.

    Mininet ed eBPF pretendono i privilegi di amministratore, quindi tutto
    quel che la campagna scrive nasce di proprietà di root. L'analisi però non
    ne ha bisogno, e girando da utente normale non riesce nemmeno a creare la
    sottocartella «analisi» dentro i risultati: si ferma con un errore di
    permessi a campagna finita, che è il momento peggiore per scoprirlo.

    SUDO_UID e SUDO_GID sono impostati da sudo e dicono chi c'era prima.
    Se non ci sono — esecuzione diretta come root — non c'è niente da rendere.
    """
    uid = os.environ.get("SUDO_UID")
    if not uid or not os.path.isdir(path):
        return
    uid = int(uid)
    gid = int(os.environ.get("SUDO_GID") or uid)
    n = 0
    for radice, cartelle, file in os.walk(path):
        for nome in cartelle + file:
            try:
                os.chown(os.path.join(radice, nome), uid, gid)
                n += 1
            except OSError:
                pass
    try:
        os.chown(path, uid, gid)
    except OSError:
        pass
    return n


def main():
    global AUG_DIR
    p = argparse.ArgumentParser(
        description="Banco di prova per augmenter",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__)
    p.add_argument("--outdir", default=os.path.join(ROOT, "results"),
                   help="cartella dei risultati (default: %(default)s)")
    p.add_argument("--aug-dir", default=AUG_DIR,
                   help="cartella che contiene static10/, ewma/, ... "
                        "(default: %(default)s)")

    # Le stesse due opzioni, accettate ANCHE dopo il sottocomando.
    #
    # argparse le vorrebbe solo prima — «testbed.py --outdir X run …» — e
    # scriverle dopo dà un «unrecognized arguments» che non suggerisce il
    # rimedio. Siccome sono le due opzioni che si passano più spesso, e la
    # posizione giusta è la meno naturale delle due, si accettano in entrambi
    # i posti.
    #
    # SUPPRESS è il pezzo che fa funzionare la cosa: senza, il sottoanalizzatore
    # scriverebbe il PROPRIO valore predefinito sopra quello dato prima di lui,
    # e «--outdir X run» tornerebbe silenziosamente al percorso predefinito —
    # un guasto peggiore dell'errore che stiamo togliendo. Con SUPPRESS
    # l'attributo viene toccato solo se l'opzione compare davvero.
    comune = argparse.ArgumentParser(add_help=False)
    comune.add_argument("--outdir", default=argparse.SUPPRESS,
                        help="come sopra; accettata anche qui")
    comune.add_argument("--aug-dir", dest="aug_dir", default=argparse.SUPPRESS,
                        help="come sopra; accettata anche qui")

    sub = p.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("check", parents=[comune],
                       help="verifica ambiente e topologia")
    c.set_defaults(func=cmd_check)

    s = sub.add_parser("shell", parents=[comune],
                       help="CLI di Mininet sulla topologia")
    s.add_argument("--bw", type=int, default=100)
    s.set_defaults(func=cmd_shell)

    t = sub.add_parser("traffico", parents=[comune],
                       help="il giro corto: topologia + scambio di pacchetti, "
                            "con il caricatore avviato a mano")
    t.add_argument("--bw", type=int, default=100,
                   help="banda del collo di bottiglia in Mbit/s (default: %(default)s)")
    t.add_argument("--obj", default="200K",
                   help="taglia dell'oggetto, o più taglie separate da virgole "
                        "(default: %(default)s)")
    t.add_argument("--rounds", type=int, default=15,
                   help="giri di richieste; ogni giro è una richiesta per client "
                        "(default: %(default)s)")
    t.add_argument("--initcwnd", type=int, default=10,
                   help="finestra iniziale sulla route di h1 (default: %(default)s)")
    t.add_argument("--metrics", action="store_true",
                   help="lascia attiva la cache tcp_metrics")
    t.add_argument("--tag", default="prova",
                   help="etichetta che finisce nei nomi dei file e nella "
                        "colonna policy (default: %(default)s)")
    t.add_argument("--iteration", type=int, default=1)
    t.add_argument("--forza", action="store_true",
                   help="esegui anche se al cgroup non risulta agganciato "
                        "nessun programma")
    t.set_defaults(func=cmd_traffico)

    k = sub.add_parser("calibrate", parents=[comune], help="banda reale e finestra statica alta")
    k.add_argument("--sweep-bw", type=int, default=100)
    k.add_argument("--sweep-values", default="10,16,24,32,48,64,96")
    k.add_argument("--sweep-objects", default="30K,200K")
    # Trenta e non dodici. Con dodici giri ogni punto ha dodici flussi per
    # client: una sola perdita in più o in meno sposta la quota di otto punti,
    # ed è così che uno zero isolato può comparire in mezzo a valori del 14 % e
    # del 31 %. Costa qualche minuto e toglie di mezzo la domanda.
    k.add_argument("--sweep-rounds", type=int, default=30)
    k.add_argument("--max-retrans-rate", type=float, default=0.05,
                   help="quota di flussi con ritrasmissioni sempre ammessa, "
                        "qualunque sia la linea di base (default: %(default)s)")
    k.add_argument("--tolleranza", type=float, default=0.02,
                   help="quanto un candidato può peggiorare le ritrasmissioni "
                        "rispetto alla finestra predefinita, in frazione "
                        "(default: %(default)s, cioè due punti percentuali)")
    k.add_argument("--alpha-shift", type=int, default=2)
    k.add_argument("--retrans-thresh", type=int, default=0)
    k.set_defaults(func=cmd_calibrate)

    r = sub.add_parser("run", parents=[comune], help="esegue la campagna")
    r.add_argument("--profile", choices=list(PROFILES), default="full")
    r.add_argument("--bandwidths", help="elenco separato da virgole, sovrascrive il profilo")
    r.add_argument("--objects", help="elenco separato da virgole")
    r.add_argument("--policies", help="elenco separato da virgole")
    r.add_argument("--iterations", type=int)
    r.add_argument("--rounds", type=int)
    r.add_argument("--static-high", type=int,
                   help="finestra della politica statica alta "
                        "(default: da calibration.json)")
    r.add_argument("--alpha-shift", type=int, default=2,
                   help="α della media mobile = 1/2^K (default: 2, cioè 1/4)")
    r.add_argument("--retrans-thresh", type=int, default=0,
                   help="soglia della regola loss-aware (default: 0)")
    r.add_argument("--iw-max-ceiling", type=int, default=IW_MAX_CEILING)
    r.add_argument("--resume", action="store_true",
                   help="salta le celle i cui CSV sono già completi")
    r.add_argument("--salta-mancanti", action="store_true",
                   dest="salta_mancanti",
                   help="procedi anche se il programma di qualche politica "
                        "non è stato compilato (predefinito: ci si ferma)")
    r.add_argument("--dry-run", action="store_true",
                   help="stampa il piano e la stima, senza eseguire")
    r.set_defaults(func=cmd_run)

    args = p.parse_args()
    AUG_DIR = os.path.abspath(args.aug_dir)

    # Anche la cartella dei risultati va assolutizzata subito, e per la stessa
    # ragione: da qui discendono la radice dei documenti e il prefisso di
    # nginx, e un percorso relativo li farebbe risolvere due volte. Meglio
    # farlo in un punto solo, all'ingresso, che ricordarsene in ogni funzione.
    args.outdir = os.path.abspath(args.outdir)
    if os.geteuid() != 0:
        sys.exit("Va eseguito come root (Mininet e eBPF lo richiedono).")
    setLogLevel("warning")
    try:
        args.func(args)
    finally:
        # Anche se il comando è fallito a metà: i file già scritti devono
        # essere leggibili e cancellabili senza sudo.
        restituisci_proprieta(args.outdir)


if __name__ == "__main__":
    main()
