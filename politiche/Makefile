# Makefile unico per le quattro politiche.
#
#   augmenter/
#   ├── Makefile            <- questo, uno solo
#   ├── augmenter.h         ┐ condivisi: esistono in UNA copia, perché sono
#   ├── augmenter.bpf.c     ┘ identici per tutte e quattro le politiche
#   ├── static10/augmenter.c
#   ├── statichigh-bpf/augmenter.c
#   ├── ewma/augmenter.c
#   └── lossaware/augmenter.c
#
# Ogni sottocartella riceve il proprio eseguibile, così ci tieni dentro anche i
# CSV di quella politica e non si mescola niente.
#
#   make                costruisce tutte le politiche presenti
#   make ewma            solo quella
#   make nuova NOME=nuova-politica   crea la cartella di una politica nuova
#   make vmlinux        rigenera vmlinux.h dal BTF del kernel in esecuzione
#   make verifier       ricarica stampando il registro del verificatore
#   make clean

CLANG   ?= clang
BPFTOOL ?= bpftool
CC      ?= gcc

# L'architettura serve al programma BPF per scegliere le definizioni giuste in
# bpf_tracing.h (registri della macchina, convenzioni di chiamata).
ARCH := $(shell uname -m | sed 's/x86_64/x86/; s/aarch64/arm64/; s/arm.*/arm/; s/ppc64le/powerpc/')

CFLAGS     ?= -O2 -g -Wall -Wextra -Wno-unused-parameter
BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) -Wall -I.
LDLIBS     := -lbpf -lelf -lz

# Le politiche sono, per definizione, le sottocartelle che contengono un
# augmenter.c. Aggiungerne una non richiede di toccare questo file.
POLICIES := $(patsubst %/augmenter.c,%,$(wildcard */augmenter.c))
BINS     := $(foreach p,$(POLICIES),$(p)/augmenter)

all: $(BINS)
	@echo
	@if [ -z "$(BINS)" ]; then \
	  echo "Nessuna politica trovata: serve almeno una sottocartella con"; \
	  echo "dentro un augmenter.c. Per crearne una:  make nuova NOME=static10"; \
	else \
	  echo "Pronti:"; for b in $(BINS); do echo "  ./$$b"; done; \
	fi

# --- vmlinux.h: le definizioni di TUTTI i tipi del kernel in esecuzione,
# --- estratte dal suo BTF. È ciò che rende il programma CO-RE: nessun header
# --- del kernel installato, nessuna dipendenza dai sorgenti.
# --- Generato UNA volta per tutte le politiche, non quattro.
vmlinux.h:
	@test -r /sys/kernel/btf/vmlinux || \
	  { echo "ERRORE: /sys/kernel/btf/vmlinux assente: il kernel non espone il BTF."; \
	    echo "        Serve un kernel compilato con CONFIG_DEBUG_INFO_BTF=y."; exit 1; }
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

vmlinux:
	rm -f vmlinux.h
	$(MAKE) vmlinux.h

# --- parte kernel: una sola, condivisa. Se il verificatore ti fa correggere
# --- qualcosa qui, lo correggi in un posto solo e tutte e quattro le politiche
# --- ne beneficiano. È l'intero motivo per cui il Makefile sta qui e non
# --- dentro le sottocartelle.
augmenter.bpf.o: augmenter.bpf.c augmenter.h vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

augmenter.skel.h: augmenter.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

# --- i caricatori: uno per sottocartella.
# --- -I. fa trovare augmenter.skel.h e augmenter.h qui in cima: le virgolette
# --- dell'#include cercano prima accanto al sorgente, non lo trovano, e
# --- ricadono su -I.
%/augmenter: %/augmenter.c augmenter.skel.h augmenter.h
	$(CC) $(CFLAGS) -I. $< -o $@ $(LDLIBS)

# --- scorciatoie: «make p3-ewma» invece di «make p3-ewma/augmenter»
$(POLICIES): %: %/augmenter

# --- crea lo scheletro di una politica nuova
nuova:
	@test -n "$(NOME)" || { echo "Uso: make nuova NOME=nuova-politica"; exit 1; }
	@test ! -d "$(NOME)" || { echo "$(NOME) esiste già"; exit 1; }
	mkdir -p "$(NOME)"
	@cp $(firstword $(wildcard */augmenter.c) /dev/null) "$(NOME)/augmenter.c" 2>/dev/null \
	  && echo "creata $(NOME)/augmenter.c (copia della prima politica: modificala)" \
	  || echo "creata $(NOME)/ — mettici dentro il tuo augmenter.c"

# --- diagnostica: ricarica il programma con il registro del verificatore al
# --- massimo dettaglio. È il comando da usare quando il caricamento fallisce,
# --- e la sua uscita è materiale del capitolo sull'implementazione.
verifier: augmenter.bpf.o
	@echo "--- registro del verificatore ---"
	-$(BPFTOOL) prog load augmenter.bpf.o /sys/fs/bpf/augmenter_test type sockops 2>&1 | tail -n 120
	-rm -f /sys/fs/bpf/augmenter_test

clean:
	rm -f $(BINS) augmenter.bpf.o augmenter.skel.h

distclean: clean
	rm -f vmlinux.h

.PHONY: all clean distclean verifier vmlinux nuova $(POLICIES)
