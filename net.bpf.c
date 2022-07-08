// +build ignore

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

u8 _SYS_CONNECT = 42;
u8 _SYS_ACCEPT = 43;

struct bpf_map_def SEC("maps") percpu_hash_map = {
    .type = BPF_MAP_TYPE_PERCPU_HASH,
    .key_size = sizeof(u8),
    .value_size = sizeof(u16),
    .max_entries = 2,
};

SEC("kprobe/sys_connect")
int BPF_PROG(connect, int sockfd, struct sockaddr *addr, int addrlen) {
  struct task_struct *t = (struct task_struct *)bpf_get_current_task();

  u32 pid_ns = BPF_CORE_READ(t, nsproxy, pid_ns_for_children, ns).inum;

  if (pid_ns == PROC_PID_INIT_INO) {
    return 0;
  }
  bpf_printk("I'm alive from sys connect!");

  return 0;
}

SEC("lsm/socket_connect")
int BPF_PROG(lsm, struct socket *sock, struct sockaddr *address, int addrlen) {
  struct task_struct *t = (struct task_struct *)bpf_get_current_task();
  u32 pid_ns = BPF_CORE_READ(t, nsproxy, pid_ns_for_children, ns).inum;

  if (pid_ns == PROC_PID_INIT_INO) {
    return 0;
  }

  u16 proto = sock->sk->sk_protocol;
  bpf_map_update_elem(&percpu_hash_map, &_SYS_CONNECT, &proto, BPF_ANY);
  bpf_printk("I'm alive from lsm connect! %d", sock->sk->sk_protocol);

  return 0;
}

SEC("kretprobe/sys_connect")
int BPF_PROG(rconnect) {
  struct task_struct *t = (struct task_struct *)bpf_get_current_task();

  u32 pid_ns = BPF_CORE_READ(t, nsproxy, pid_ns_for_children, ns).inum;

  if (pid_ns == PROC_PID_INIT_INO) {
    return 0;
  }
  u16 *prot = bpf_map_lookup_elem(&percpu_hash_map, &_SYS_CONNECT);
  if (prot) {
    bpf_printk("I'm alive from ret sys connect!%d", *prot);
  }

  return 0;
}

SEC("kprobe/sys_accept")
int BPF_PROG(accept, int sockfd, struct sockaddr *addr, int addrlen) {
  struct task_struct *t = (struct task_struct *)bpf_get_current_task();

  u32 pid_ns = BPF_CORE_READ(t, nsproxy, pid_ns_for_children, ns).inum;

  if (pid_ns == PROC_PID_INIT_INO) {
    return 0;
  }
  bpf_printk("I'm alive from sys accept!");

  return 0;
}

SEC("lsm/socket_accept")
int BPF_PROG(lsma, struct socket *sock) {
  struct task_struct *t = (struct task_struct *)bpf_get_current_task();
  u32 pid_ns = BPF_CORE_READ(t, nsproxy, pid_ns_for_children, ns).inum;

  if (pid_ns == PROC_PID_INIT_INO) {
    return 0;
  }

  u16 proto = sock->sk->sk_protocol;
  bpf_map_update_elem(&percpu_hash_map, &_SYS_ACCEPT, &proto, BPF_ANY);
  bpf_printk("I'm alive from lsm accept! %d", sock->sk->sk_protocol);

  return 0;
}

SEC("kretprobe/sys_accept")
int BPF_PROG(raccept) {
  struct task_struct *t = (struct task_struct *)bpf_get_current_task();

  u32 pid_ns = BPF_CORE_READ(t, nsproxy, pid_ns_for_children, ns).inum;

  if (pid_ns == PROC_PID_INIT_INO) {
    return 0;
  }
  u16 *prot = bpf_map_lookup_elem(&percpu_hash_map, &_SYS_ACCEPT);
  if (prot) {
    bpf_printk("I'm alive from ret sys accept!%d", *prot);
  }

  return 0;
}