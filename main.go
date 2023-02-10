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

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang bpf test.bpf.c -- -I/usr/include/bpf -O2 -g

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

	kinoc, err := link.AttachLSM(link.LSMOptions{Program: objs.InodeCreate})
	if err != nil {
		log.Fatalf("opening lsm: %s", err)
	}
	defer kinoc.Close()

	kpathnmkn, err := link.AttachLSM(link.LSMOptions{Program: objs.PathMknod})
	if err != nil {
		log.Fatalf("opening lsm: %s", err)
	}
	defer kpathnmkn.Close()

	kinol, err := link.AttachLSM(link.LSMOptions{Program: objs.InodeLink})
	if err != nil {
		log.Fatalf("opening lsm: %s", err)
	}
	defer kinol.Close()

	kinoul, err := link.AttachLSM(link.LSMOptions{Program: objs.InodeUnlink})
	if err != nil {
		log.Fatalf("opening lsm: %s", err)
	}
	defer kinoul.Close()

	kpathl, err := link.AttachLSM(link.LSMOptions{Program: objs.PathLink})
	if err != nil {
		log.Fatalf("opening lsm: %s", err)
	}
	defer kpathl.Close()

	kapthul, err := link.AttachLSM(link.LSMOptions{Program: objs.PathUnlink})
	if err != nil {
		log.Fatalf("opening lsm: %s", err)
	}
	defer kapthul.Close()

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for range ticker.C {

	}
}
