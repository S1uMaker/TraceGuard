SHELL := /bin/bash
GO ?= go
CLANG ?= clang
BUILD_DIR := build
MULTIARCH := $(shell gcc -dumpmachine 2>/dev/null)
BPF_FLAGS := -O2 -g -target bpfel -Wall -Werror -I/usr/include/$(MULTIARCH)

.PHONY: all deps bpf build fmt help
all: build

deps:
	$(GO) mod download

bpf: $(BUILD_DIR)/exec.bpf.o

$(BUILD_DIR)/exec.bpf.o: bpf/exec.bpf.c
	@case "$$(uname -m)" in x86_64|aarch64) ;; *) echo 'Only Linux amd64/arm64 is supported'; exit 1;; esac
	mkdir -p $(BUILD_DIR)
	$(CLANG) $(BPF_FLAGS) -c $< -o $@

build: deps bpf
	CGO_ENABLED=0 $(GO) build -trimpath -mod=mod -o $(BUILD_DIR)/traceguard ./cmd/traceguard

fmt:
	$(GO) fmt ./...

help:
	@echo 'make build : download pinned Go dependencies and compile C/eBPF + Go on Ubuntu'
	@echo 'make fmt   : format Go source'
