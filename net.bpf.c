// +build ignore

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

enum event_id { socket, bind, connect, listen, accept, send, recv };

#define MAX_BUFFER_SIZE 32768
#define MAX_STRING_SIZE 256
#define MAX_BUFFERS 1
#define PATH_BUFFER 0

typedef struct buffers {
  char buf[MAX_BUFFER_SIZE];
} bufs_t;

#undef container_of
#define container_of(ptr, type, member)                                        \
  ({                                                                           \
    const typeof(((type *)0)->member) *__mptr = (ptr);                         \
    (type *)((char *)__mptr - offsetof(type, member));                         \
  })

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, u32);
  __type(value, bufs_t);
  __uint(max_entries, MAX_BUFFERS);
} bufs SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, u32);
  __type(value, u32);
  __uint(max_entries, MAX_BUFFERS);
} bufs_off SEC(".maps");

u8 _SYS_CONNECT = 42;
u8 _SYS_ACCEPT = 43;

struct bpf_map_def SEC("maps") percpu_hash_map = {
    .type = BPF_MAP_TYPE_PERCPU_HASH,
    .key_size = sizeof(u8),
    .value_size = sizeof(u16),
    .max_entries = 2,
};

static __always_inline bufs_t *get_buf(int idx) {
  return bpf_map_lookup_elem(&bufs, &idx);
}

static __always_inline void set_buf_off(int buf_idx, u32 new_off) {
  bpf_map_update_elem(&bufs_off, &buf_idx, &new_off, BPF_ANY);
}

static __always_inline u32 *get_buf_off(int buf_idx) {
  return bpf_map_lookup_elem(&bufs_off, &buf_idx);
}

static inline struct mount *real_mount(struct vfsmount *mnt) {
  return container_of(mnt, struct mount, mnt);
}

static __always_inline bool prepend_path(struct path *path, bufs_t *string_p) {
  char slash = '/';
  char null = '\0';
  int offset = MAX_STRING_SIZE;

  if (path == NULL || string_p == NULL) {
    return false;
  }

  struct dentry *dentry = path->dentry;
  struct vfsmount *vfsmnt = path->mnt;

  struct mount *mnt = real_mount(vfsmnt);

  struct dentry *parent;
  struct dentry *mnt_root;
  struct mount *m;
  struct qstr d_name;

#pragma unroll
  for (int i = 0; i < 30; i++) {
    parent = BPF_CORE_READ(dentry, d_parent);
    mnt_root = BPF_CORE_READ(vfsmnt, mnt_root);

    if (dentry == mnt_root) {
      m = BPF_CORE_READ(mnt, mnt_parent);
      if (mnt != m) {
        dentry = BPF_CORE_READ(mnt, mnt_mountpoint);
        mnt = m;
        continue;
      }
      break;
    }

    if (dentry == parent) {
      break;
    }

    // get d_name
    d_name = BPF_CORE_READ(dentry, d_name);

    offset -= (d_name.len + 1);
    if (offset < 0)
      break;

    int sz = bpf_probe_read_str(
        &(string_p->buf[(offset) & (MAX_STRING_SIZE - 1)]),
        (d_name.len + 1) & (MAX_STRING_SIZE - 1), d_name.name);
    if (sz > 1) {
      bpf_probe_read(
          &(string_p->buf[(offset + d_name.len) & (MAX_STRING_SIZE - 1)]), 1,
          &slash);
    } else {
      offset += (d_name.len + 1);
    }

    dentry = parent;
  }

  if (offset == MAX_STRING_SIZE) {
    return false;
  }

  bpf_probe_read(&(string_p->buf[MAX_STRING_SIZE - 1]), 1, &null);
  offset--;

  bpf_probe_read(&(string_p->buf[offset & (MAX_STRING_SIZE - 1)]), 1, &slash);
  set_buf_off(PATH_BUFFER, offset);
  return true;
}

SEC("kprobe/security_socket_create")
int BPF_PROG(lsmsocket, int family, int type, int protocol) {
  struct task_struct *t = (struct task_struct *)bpf_get_current_task();
  u32 pid_ns = BPF_CORE_READ(t, nsproxy, pid_ns_for_children, ns).inum;

  if (pid_ns == PROC_PID_INIT_INO) {
    return 0;
  }

  struct file *file_p = BPF_CORE_READ(t, mm, exe_file);
  if (file_p == NULL)
    return 0;
  bufs_t *src_buf = get_buf(PATH_BUFFER);
  if (src_buf == NULL)
    return 0;
  struct path f_src = BPF_CORE_READ(file_p, f_path);
  if (!prepend_path(&f_src, src_buf))
    return 0;

  u32 *src_offset = get_buf_off(PATH_BUFFER);
  if (src_offset == NULL)
    return 0;

  void *ptr = &src_buf->buf[*src_offset];
  char p[MAX_STRING_SIZE];
  bpf_probe_read_str(p, MAX_STRING_SIZE, ptr);

  bpf_printk("I'm alive from lsm socket! %d called by %s", protocol, p);

  return 0;
}

#define LSM_NET(name, id)                                                      \
  int BPF_PROG(name, struct socket *sock) {                                    \
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();      \
    u32 pid_ns = BPF_CORE_READ(t, nsproxy, pid_ns_for_children, ns).inum;      \
                                                                               \
    if (pid_ns == PROC_PID_INIT_INO) {                                         \
      return 0;                                                                \
    }                                                                          \
                                                                               \
    struct file *file_p = BPF_CORE_READ(t, mm, exe_file);                      \
    if (file_p == NULL)                                                        \
      return 0;                                                                \
    bufs_t *src_buf = get_buf(PATH_BUFFER);                                    \
    if (src_buf == NULL)                                                       \
      return 0;                                                                \
    struct path f_src = BPF_CORE_READ(file_p, f_path);                         \
    if (!prepend_path(&f_src, src_buf))                                        \
      return 0;                                                                \
                                                                               \
    u32 *src_offset = get_buf_off(PATH_BUFFER);                                \
    if (src_offset == NULL)                                                    \
      return 0;                                                                \
                                                                               \
    void *ptr = &src_buf->buf[*src_offset];                                    \
    char p[MAX_STRING_SIZE];                                                   \
    bpf_probe_read_str(p, MAX_STRING_SIZE, ptr);                               \
                                                                               \
    u16 proto = BPF_CORE_READ(sock, sk, sk_protocol);                          \
    bpf_printk("I'm alive from lsm %d! %d called by %s", id, proto, p);        \
                                                                               \
    return 0;                                                                  \
  }

SEC("kprobe/security_socket_bind")
LSM_NET(lsmb, bind);

SEC("kprobe/security_socket_connect")
LSM_NET(lsmc, connect);

SEC("kprobe/security_socket_listen")
LSM_NET(lsml, listen);

SEC("kprobe/security_socket_accept")
LSM_NET(lsma, accept);

SEC("kprobe/security_socket_sendmsg")
LSM_NET(lsmsend, send);

SEC("kprobe/security_socket_recvmsg")
LSM_NET(lsmrecv, recv);