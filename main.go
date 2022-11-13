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

	kpsock, err := link.Kprobe("security_socket_create", objs.Lsmsocket, nil)
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer kpsock.Close()

	kpb, err := link.Kprobe("security_socket_bind", objs.Lsmb, nil)
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer kpb.Close()

	kpc, err := link.Kprobe("security_socket_connect", objs.Lsmc, nil)
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer kpc.Close()

	kpl, err := link.Kprobe("security_socket_listen", objs.Lsml, nil)
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer kpl.Close()

	kpa, err := link.Kprobe("security_socket_accept", objs.Lsma, nil)
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer kpa.Close()

	kpsend, err := link.Kprobe("security_socket_sendmsg", objs.Lsmsend, nil)
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer kpsend.Close()

	kprecv, err := link.Kprobe("security_socket_recvmsg", objs.Lsmrecv, nil)
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer kprecv.Close()

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for range ticker.C {

	}
}
