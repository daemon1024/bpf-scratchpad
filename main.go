//go:build linux
// +build linux

package main

import (
	"log"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang bpf net.bpf.c -- -I/usr/include/bpf -O2 -g

func main() {

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: "/sys/fs/bpf",
		},
	}); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	kpc, err := link.Kprobe("sys_connect", objs.Connect, nil)
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer kpc.Close()

	kpsc, err := link.AttachLSM(link.LSMOptions{Program: objs.Lsm})
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer kpsc.Close()

	kprc, err := link.Kretprobe("sys_connect", objs.Rconnect, nil)
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer kprc.Close()

	kpa, err := link.Kprobe("sys_accept", objs.Accept, nil)
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer kpa.Close()

	kpsa, err := link.AttachLSM(link.LSMOptions{Program: objs.Lsma})
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer kpsa.Close()

	kpra, err := link.Kretprobe("sys_accept", objs.Raccept, nil)
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer kpra.Close()

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for range ticker.C {

	}
}
