CLANG ?= clang
CC ?= gcc
BPFTOOL ?= bpftool

BPF_C := scx_lottery.bpf.c
BPF_O := scx_lottery.bpf.o
BPF_SKEL := scx_lottery.bpf.skel.h
USER_C := scx_lottery.c
OUTPUT := scx_lottery

BPF_ARCH ?= x86
BPF_CFLAGS ?= -g -O2 -target bpf -D__TARGET_ARCH_$(BPF_ARCH)
USER_CFLAGS ?= -g -O2
USER_LDLIBS ?= -lbpf

all: $(OUTPUT)

$(BPF_O): $(BPF_C)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

$(BPF_SKEL): $(BPF_O)
	$(BPFTOOL) gen skeleton $< > $@

$(OUTPUT): $(USER_C) $(BPF_SKEL)
	$(CC) $(USER_CFLAGS) -I. -o $@ $(USER_C) $(USER_LDLIBS)

clean:
	rm -f $(BPF_O) $(BPF_SKEL) $(OUTPUT)

.PHONY: all clean
