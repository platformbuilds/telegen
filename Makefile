BPF_CLANG ?= clang
BPF_LLVM_STRIP ?= llvm-strip

BPF_SRCS := bpf/tcpevents.bpf.c
BPF_OUT_EL := internal/capture/ebpf/tcpevents_bpfel.o
BPF_OUT_EB := internal/capture/ebpf/tcpevents_bpfeb.o

.PHONY: build run bpf docker

build:
	go mod tidy
	go build ./cmd/telegen

run:
	go run ./cmd/telegen --config ./api/config.example.yaml

bpf:
	$(BPF_CLANG) -O2 -g -target bpf -D__TARGET_ARCH_x86 -c $(BPF_SRCS) -o $(BPF_OUT_EL)
	$(BPF_LLVM_STRIP) -g $(BPF_OUT_EL)
	$(BPF_CLANG) -O2 -g -target bpf -D__TARGET_ARCH_arm64 -c $(BPF_SRCS) -o $(BPF_OUT_EB)
	$(BPF_LLVM_STRIP) -g $(BPF_OUT_EB)
	@echo "Built $(BPF_OUT_EL) and $(BPF_OUT_EB)"

docker:
	docker build -t telegen:dev .
