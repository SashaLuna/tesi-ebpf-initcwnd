# eBPF per il monitoraggio e l'adattamento delle connessioni TCP: caso di studio sulla finestra iniziale di congestione

Materiale della tesi di laurea triennale in Informatica, Università di Pisa —
relatrice prof.ssa Paganelli.

Il lavoro misura se la finestra iniziale di congestione (*initial congestion
window*, IW) di TCP convenga adattarla per destinazione a partire da ciò che il
server osserva delle connessioni precedenti, invece di lasciarla al valore
fisso di dieci segmenti che il kernel usa per impostazione predefinita. La
decisione è presa nello spazio utente e applicata da un programma eBPF di tipo
`sockops` agganciato a un cgroup, che imposta la finestra sulla connessione
appena accettata e restituisce un record per ogni connessione chiusa.

Il repository contiene i programmi, il banco di prova e i dati grezzi della
campagna di misura: tutto ciò che serve a rileggere i numeri del capitolo di
valutazione o a rieseguire gli esperimenti.

## Struttura

```
politiche/          il programma eBPF, l'intestazione condivisa e i caricatori
  augmenter.bpf.c     programma sockops: unico, identico per tutte le politiche
  augmenter.h         struct aug_stats, layout condiviso kernel/spazio utente
  Makefile            costruisce tutte le politiche presenti
  static10/           caricatore in sola osservazione: non scrive mai in iw_map
  statichigh-bpf/     finestra statica imposta via eBPF (--iw N)
  ewma/               media mobile esponenziale della finestra osservata
  lossaware/          come sopra, con penalizzazione sulle ritrasmissioni
banco/              topologia Mininet, protocollo sperimentale, orchestrazione
analisi/            stats.py (tabelle) e conformita.py (controlli sui dati)
risultati/
  campagna/           campagna definitiva del 10-11 settembre 2026 + tabelle .tex
  percorso-ebpf/      misura di controllo: stessa finestra, due vie di applicazione
  taratura/           esplorazione della finestra statica alta
```

## Le configurazioni e i quattro programmi

Le configurazioni messe a confronto non corrispondono una a uno ai programmi:
tre di esse si ottengono dallo stesso caricatore in sola osservazione,
cambiando ciò che sta *intorno* a TCP anziché il programma.

Queste sei formano la griglia della campagna:

| configurazione | finestra iniziale | come è ottenuta |
|---|---|---|
| `static10` | 10 segmenti | route predefinita, caricatore in sola osservazione |
| `metrics` | 10 segmenti | come sopra, con la cache `tcp_metrics` lasciata attiva |
| `statichigh` | valore della taratura | `ip route … initcwnd N` sulla route, stesso caricatore |
| `ewma` | stimata | media mobile esponenziale, α = 1/4 |
| `lossaware` | stimata | come `ewma`, dimezzata dove ci sono ritrasmissioni |
| `lossaware-disc` | stimata | come sopra, con il discriminante `--crescita-max` |

Una settima configurazione, `statichigh-bpf`, sta **fuori dalla griglia** e
compare solo nella misura di controllo: applica la stessa finestra di
`statichigh`, ma imponendola da eBPF (`politiche/statichigh-bpf`) invece che
sulla route. Il confronto fra le due isola il costo del percorso eBPF
dall'effetto della finestra, ed è la ragione per cui esiste
`risultati/percorso-ebpf/`.

Si noti infine che `lossaware` e `lossaware-disc` sono lo **stesso programma**
con un'opzione in più: il discriminante distingue le perdite dovute alla
raffica iniziale da quelle in cui è lo slow start a superare la capacità del
percorso.

## Requisiti

Il banco gira dentro una macchina virtuale Linux (durante il lavoro: Lima su
macOS, kernel 6.8 su aarch64). Servono:

- un kernel compilato con `CONFIG_DEBUG_INFO_BTF=y` — `/sys/kernel/btf/vmlinux`
  deve esistere, perché da lì si genera `vmlinux.h`;
- `clang`, `bpftool`, `libbpf-dev`, `libelf`, `zlib`;
- `python3`, Mininet, `nginx`, `curl`, `iperf3`;
- privilegi di root per agganciare il programma al cgroup e per costruire la
  topologia.

`banco/00-install.sh` installa le dipendenze su una Debian/Ubuntu pulita.

## Compilazione

```sh
cd politiche
make
```

`make` genera prima `vmlinux.h` dal BTF del kernel in esecuzione, poi compila
il programma eBPF una sola volta e infine i quattro caricatori, uno per
sottocartella. `make ewma` costruisce solo quella; `make verifier` ricarica il
programma stampando il registro del verificatore, utile quando il caricamento
fallisce.

`vmlinux.h` e `augmenter.skel.h` **non sono versionati**, ed è voluto: sono
generati dal kernel della macchina su cui si compila, e versionarli
imporrebbe a chi clona il kernel usato qui invece del suo — il contrario
della portabilità che CO-RE rende possibile.

## Riprodurre le misure

```sh
sudo python3 banco/testbed.py check       # topologia, RTT, banda: un minuto
sudo python3 banco/testbed.py calibrate   # banda reale e finestra statica alta
sudo python3 banco/testbed.py traffico    # un esperimento, caricatore avviato a mano
sudo python3 banco/testbed.py run         # la campagna intera
```

`check` costruisce la topologia, verifica i parametri derivati e smonta tutto.
`traffico` è il giro corto: costruisce la topologia ed esegue lo scambio, ma il
caricatore lo si avvia a mano in un altro terminale — è il modo per osservare
una singola politica mentre lavora. `run` ripete `traffico` su tutta la griglia,
avviando e fermando il caricatore a ogni cella. `testbed.py --help` documenta
tutte le opzioni.

## I dati

**Campagna definitiva** (`risultati/campagna/`), eseguita il 10-11 settembre
2026: le sei configurazioni della griglia, tre valori di banda (20, 50,
100 Mbit/s), sei taglie di oggetto (1 KB, 10 KB, 30 KB, 200 KB, 1 MB, 10 MB),
dieci iterazioni per cella — 6 × 3 × 6 × 10 = 1080 celle, per un totale di
48 600 connessioni TCP, tutte ricostruite
dalla giunzione fra la misura lato client e quella lato server, senza scarti.

- `connessioni.csv` — una riga per connessione TCP, giunzione completa;
- `connessioni_itNN.csv` — la stessa cosa, divisa per iterazione;
- `riepilogo.csv`, `riepilogo_per_iterazione.csv`, `riepilogo_aggregato.csv` —
  aggregati per cella, con le dispersioni;
- `tabelle/` — i `.tex` generati da `analisi/stats.py`, quelli che compaiono
  nella tesi;
- `campagna.log` — il registro dell'esecuzione reale.

La giunzione fra le due misure usa la porta effimera del client: `curl` la
riporta con `%{local_port}`, e il programma eBPF la registra nel campo `dport`
del record emesso alla transizione a `TCP_CLOSE`. Le metriche lato client sono
il tempo di completamento e il goodput; quelle lato server la finestra
applicata, la finestra di congestione massima, il RTT smussato e le
ritrasmissioni.

**Misura di controllo** (`risultati/percorso-ebpf/`): `statichigh` contro
`statichigh-bpf` a 20 Mbit/s su oggetti da 200 KB e 1 MB, dieci iterazioni,
1800 connessioni. Serve a stabilire che le differenze osservate nella campagna
vengono dalla finestra e non dal fatto che un programma eBPF sta agganciato al
cgroup.

**Taratura** (`risultati/taratura/`): l'esplorazione con cui è stato scelto il
valore della finestra statica alta. Sono state provate sette finestre — 10, 16,
24, 32, 48, 64 e 96 segmenti — su oggetti da 30 KB e 200 KB, 180 flussi
ciascuna, confrontando i risultati con la linea di base coppia per coppia
(taglia, client) anziché su un aggregato.

Ne sono usciti **24 segmenti**, il valore usato da `statichigh`: il tempo di
completamento mediano scende da 80,5 ms a 43,4 ms e oltre quella soglia non
migliora più, mentre da 48 segmenti in su cominciano a comparire ritrasmissioni
sul client a RTT intermedio (1 flusso su 30 a 48, 2 a 64, 15 a 96). Il client
più vicino ritrasmette invece a ogni finestra, compresa quella predefinita: sul
suo percorso è lo slow start a superare la capacità, non la raffica iniziale.
La raccomandazione, i tempi e le bande misurate con iperf3 stanno in
`risultati/campagna/calibration.json`.

## Analisi

```sh
python3 analisi/stats.py risultati/campagna/connessioni.csv
python3 analisi/conformita.py risultati/campagna/connessioni.csv
```

`stats.py` produce gli aggregati e le tabelle LaTeX. `conformita.py` è il
controllo di merito sui dati: verifica che le politiche passive non tocchino
davvero la finestra, che quelle attive intervengano, che la stima si muova e
che il dimezzamento scatti dove ci sono ritrasmissioni. È il passo che
distingue una campagna riuscita da una campagna che sembra riuscita.

## Nota sui sorgenti

Nelle cartelle sotto `politiche/` i caricatori portano i nomi delle
configurazioni della tesi; durante lo sviluppo si chiamavano `p1-default`,
`p2-statica`, `p3-ewma` e `p4-lossaware`. I nomi sono stati allineati anche
dentro `banco/testbed.py`. A parte questo e la riscrittura dei commenti, il
codice qui pubblicato è quello che ha prodotto i dati in `risultati/`.
