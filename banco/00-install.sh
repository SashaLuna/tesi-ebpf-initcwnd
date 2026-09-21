#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# 00-install.sh — prepara la macchina per la campagna di prove.
#
# Da eseguire UNA VOLTA SOLA nella VM Linux (Lima, Ubuntu/Debian). Idempotente:
# rieseguirlo non fa danni. Al termine stampa un riepilogo dell'ambiente da
# riportare nel capitolo «ambiente sperimentale».
#
#   sudo ./00-install.sh
# ---------------------------------------------------------------------------
set -euo pipefail

BOLD=$'\e[1m'; RED=$'\e[31m'; GRN=$'\e[32m'; YLW=$'\e[33m'; OFF=$'\e[0m'
say()  { printf '%s==>%s %s\n' "$BOLD" "$OFF" "$*"; }
ok()   { printf '  %s[ok]%s   %s\n'   "$GRN" "$OFF" "$*"; }
warn() { printf '  %s[att]%s  %s\n'   "$YLW" "$OFF" "$*"; }
die()  { printf '  %s[err]%s  %s\n'   "$RED" "$OFF" "$*"; exit 1; }

[ "$(id -u)" -eq 0 ] || die "eseguire con sudo."

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$HERE")"
AUG="$ROOT/augmenter"

# ---------------------------------------------------------------------------
say "1/6  Pacchetti"
# ---------------------------------------------------------------------------
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq

PKGS=(
  build-essential clang llvm libelf-dev zlib1g-dev libbpf-dev pkg-config
  mininet openvswitch-switch openvswitch-common
  nginx-light curl iperf3 ethtool iproute2 net-tools
  python3 python3-pip
)
apt-get install -y -qq "${PKGS[@]}"
ok "pacchetti di base installati"

# bpftool: su Ubuntu sta nel pacchetto degli strumenti del kernel in esecuzione,
# il cui nome cambia a ogni versione. Si prova nell'ordine più probabile.
if ! command -v bpftool >/dev/null 2>&1; then
  for p in "linux-tools-$(uname -r)" bpftool linux-tools-generic linux-tools-common; do
    apt-get install -y -qq "$p" 2>/dev/null && break || true
  done
fi
if ! command -v bpftool >/dev/null 2>&1; then
  # I pacchetti linux-tools installano il binario in una directory per versione
  # e non sempre creano il collegamento in PATH.
  CAND=$(ls -1 /usr/lib/linux-tools*/bpftool 2>/dev/null | head -n1 || true)
  [ -n "$CAND" ] && ln -sf "$CAND" /usr/local/sbin/bpftool || true
fi
command -v bpftool >/dev/null 2>&1 \
  && ok "bpftool: $(bpftool version 2>&1 | head -n1)" \
  || die "bpftool non trovato: installarlo a mano prima di proseguire."

# ---------------------------------------------------------------------------
say "2/6  Requisiti del kernel"
# ---------------------------------------------------------------------------
KREL=$(uname -r)
need_cfg() {
  local sym=$1 src=""
  for f in "/boot/config-$KREL" /proc/config.gz; do
    [ -r "$f" ] && src=$f && break
  done
  if [ -z "$src" ]; then warn "configurazione del kernel non leggibile: $sym non verificato"; return; fi
  if { [ "$src" = /proc/config.gz ] && zcat "$src" || cat "$src"; } | grep -q "^$sym=y"; then
    ok "$sym"
  else
    warn "$sym NON attivo: alcune funzioni potrebbero non caricarsi"
  fi
}
need_cfg CONFIG_BPF_SYSCALL
need_cfg CONFIG_CGROUP_BPF
need_cfg CONFIG_DEBUG_INFO_BTF
need_cfg CONFIG_BPF_JIT
need_cfg CONFIG_NET_SCH_NETEM
need_cfg CONFIG_NET_SCH_HTB

[ -r /sys/kernel/btf/vmlinux ] \
  && ok "BTF del kernel presente ($(stat -c%s /sys/kernel/btf/vmlinux) byte)" \
  || die "/sys/kernel/btf/vmlinux assente: senza BTF non si può generare vmlinux.h."

if [ -f /sys/fs/cgroup/cgroup.controllers ]; then
  ok "cgroup v2 unificato montato su /sys/fs/cgroup"
else
  die "cgroup v2 non montato in modo unificato: l'aggancio del programma sockops lo richiede."
fi

# ---------------------------------------------------------------------------
say "3/6  Open vSwitch"
# ---------------------------------------------------------------------------
systemctl enable --now openvswitch-switch >/dev/null 2>&1 || true
if ovs-vsctl show >/dev/null 2>&1; then
  ok "ovs-vswitchd attivo"
else
  warn "ovs-vswitchd non risponde; provo a riavviarlo"
  systemctl restart openvswitch-switch || true
  ovs-vsctl show >/dev/null 2>&1 && ok "ora attivo" || die "Open vSwitch non parte."
fi
mn -c >/dev/null 2>&1 || true
ok "residui di Mininet ripuliti"

# ---------------------------------------------------------------------------
say "4/6  Compilazione di augmenter"
# ---------------------------------------------------------------------------
# Una cartella per politica, un eseguibile ciascuna. Si compila quello che c'è:
# se p3-ewma/ e p4-lossaware/ non esistono ancora, il make riesce lo stesso e
# la campagna salterà quelle politiche invece di fermarsi.
[ -d "$AUG" ] || die "cartella $AUG non trovata: l'albero non è quello atteso."
make -C "$AUG" clean >/dev/null 2>&1 || true
make -C "$AUG" 2>&1 | sed 's/^/      /'

BINS=$(ls -1 "$AUG"/*/augmenter 2>/dev/null || true)
[ -n "$BINS" ] || die "compilazione fallita: nessun eseguibile prodotto."
for b in $BINS; do ok "binario: $b"; done

# Prova di caricamento a vuoto: verifica che il verificatore accetti il
# programma PRIMA che parta una campagna di ore. La comparsa del CSV è il
# segnale che il caricamento e l'aggancio al cgroup sono riusciti — il
# programma scrive l'intestazione solo dopo entrambi.
say "      prova di caricamento e aggancio"
SMOKE_BIN="$AUG/p1-default/augmenter"
if [ -x "$SMOKE_BIN" ]; then
  rm -f /tmp/aug-smoke.csv
  timeout 5 "$SMOKE_BIN" --csv /tmp/aug-smoke.csv >/tmp/aug-smoke.log 2>&1 || true
  if [ -s /tmp/aug-smoke.csv ]; then
    ok "il programma si carica e si aggancia al cgroup"
  else
    echo "--- /tmp/aug-smoke.log ---"; cat /tmp/aug-smoke.log
    die "caricamento fallito: sopra c'è il registro del verificatore.
       Per il registro completo:  make -C $AUG verifier"
  fi
else
  warn "p1-default non compilato: prova di caricamento saltata"
fi

# ---------------------------------------------------------------------------
say "5/6  Parametri globali di sistema"
# ---------------------------------------------------------------------------
# net.core.* NON è per spazio dei nomi di rete: va impostato una volta sola qui,
# mentre net.ipv4.tcp_[rw]mem lo è, e va impostato host per host (lo fa
# testbed.py). Senza questi valori il buffer di trasmissione, e non la finestra
# di congestione, diventerebbe il fattore limitante a 1 Gbit/s con 52 ms di RTT
# (prodotto banda-ritardo ≈ 6,5 MB).
cat >/etc/sysctl.d/99-augmenter-testbed.conf <<'EOF'
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.core.netdev_max_backlog = 5000
net.core.somaxconn = 4096
EOF
sysctl -q -p /etc/sysctl.d/99-augmenter-testbed.conf
ok "buffer di sistema dimensionati per 1 Gbit/s × 52 ms"

# nginx di sistema disattivato: la campagna avvia la propria istanza dentro lo
# spazio dei nomi di h1, con una configurazione dedicata.
systemctl disable --now nginx >/dev/null 2>&1 || true
ok "nginx di sistema disattivato (la campagna ne avvia uno proprio)"

# ---------------------------------------------------------------------------
say "6/6  Riepilogo dell'ambiente"
# ---------------------------------------------------------------------------
SUM="$ROOT/ambiente.txt"
{
  echo "Ambiente sperimentale — rilevato il $(date -Is)"
  echo
  echo "sistema           : $(. /etc/os-release; echo "$PRETTY_NAME") ($(uname -m))"
  echo "kernel            : $(uname -r)"
  echo "CPU               : $(nproc) processori — $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2- | xargs || uname -p)"
  echo "memoria           : $(awk '/MemTotal/{printf "%.1f GiB", $2/1048576}' /proc/meminfo)"
  echo "clang             : $(clang --version | head -n1)"
  echo "libbpf            : $(pkg-config --modversion libbpf 2>/dev/null || echo 'n/d')"
  echo "bpftool           : $(bpftool version 2>&1 | head -n1)"
  echo "mininet           : $(mn --version 2>&1 | head -n1)"
  echo "Open vSwitch      : $(ovs-vsctl --version | head -n1)"
  echo "nginx             : $(nginx -v 2>&1)"
  echo "curl              : $(curl --version | head -n1)"
  echo "iperf3            : $(iperf3 --version | head -n1)"
  echo "controllo cong.   : $(sysctl -n net.ipv4.tcp_congestion_control)"
  echo "disponibili       : $(sysctl -n net.ipv4.tcp_available_congestion_control)"
} | tee "$SUM"

echo
ok "installazione completata. Riepilogo salvato in $SUM"
cat <<EOF

Prossimi passi:
  sudo python3 $ROOT/testbed/testbed.py check       verifica rapida della topologia
  sudo python3 $ROOT/testbed/testbed.py calibrate   banda reale e scelta della IW statica alta
  sudo python3 $ROOT/testbed/testbed.py run --profile quick    prova generale (~12 min)
  sudo python3 $ROOT/testbed/testbed.py run --profile full     campagna completa

EOF
