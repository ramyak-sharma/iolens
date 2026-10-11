// Package bpfsrc holds the compiled bpf object and the go types bpf2go
// generates for its maps. regenerate with make generate after touching
// anything under bpf/
package bpfsrc

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang -cflags "-O2 -g -Wall -Werror" -type hist -type hist_key -type inflight_req Iolens ../../bpf/iolens.bpf.c -- -I../../bpf
