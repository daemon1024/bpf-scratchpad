// +build ignore

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

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

static inline struct mount *real_mount(struct vfsmount *mnt) {
  return container_of(mnt, struct mount, mnt);
}
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

static __always_inline bufs_t *get_buf(int idx) {
  return bpf_map_lookup_elem(&bufs, &idx);
}

static __always_inline void set_buf_off(int buf_idx, u32 new_off) {
  bpf_map_update_elem(&bufs_off, &buf_idx, &new_off, BPF_ANY);
}

static __always_inline u32 *get_buf_off(int buf_idx) {
  return bpf_map_lookup_elem(&bufs_off, &buf_idx);
}

static __always_inline void prepend_path_dentry(struct dentry *dentry,
                                                bufs_t *string_p,
                                                struct task_struct *t) {
  char slash = '/';
  char null = '\0';
  int offset = MAX_STRING_SIZE;

  // struct vfsmount vfsmnt = BPF_CORE_READ(t, nsproxy, mnt_ns, root, mnt);
  struct mount *mnt = BPF_CORE_READ(t, nsproxy, mnt_ns, root);

  struct dentry *parent;
  struct dentry *mnt_root;
  struct mount *m;
  struct qstr d_name;

#pragma unroll
  for (int i = 0; i < 30; i++) {
    parent = BPF_CORE_READ(dentry, d_parent);
    mnt_root = BPF_CORE_READ(t, nsproxy, mnt_ns, root, mnt_mountpoint);
    // mnt_root = BPF_CORE_READ(t, nsproxy, mnt_ns, root, mnt).mnt_root;

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
    return;
  }

  bpf_probe_read(&(string_p->buf[MAX_STRING_SIZE - 1]), 1, &null);
  offset--;

  bpf_probe_read(&(string_p->buf[offset & (MAX_STRING_SIZE - 1)]), 1, &slash);
  set_buf_off(PATH_BUFFER, offset);
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

SEC("lsm/inode_create")
int BPF_PROG(inode_create, struct inode *inode_dir, struct dentry *dent,
             umode_t mode) {
  struct task_struct *t = (struct task_struct *)bpf_get_current_task();
  u32 pid_ns = BPF_CORE_READ(t, nsproxy, pid_ns_for_children, ns).inum;

  if (pid_ns == PROC_PID_INIT_INO) {
    return 0;
  }

  u32 mnt_ns_id = BPF_CORE_READ(t, nsproxy, mnt_ns, ns).inum;

  bufs_t *string_p = get_buf(PATH_BUFFER);
  if (string_p == NULL)
    return 0;

  prepend_path_dentry(dent, string_p, t);

  u32 *src_offset = get_buf_off(PATH_BUFFER);
  if (src_offset == NULL)
    return 0;

  bpf_printk("inode_create mnt id - %u ! %s", mnt_ns_id,
             &string_p->buf[*src_offset]);

  return 0;
}


SEC("lsm/path_mknod")
int BPF_PROG(path_mknod, struct path *dir, struct dentry *dentry) {
  struct task_struct *t = (struct task_struct *)bpf_get_current_task();
  u32 pid_ns = BPF_CORE_READ(t, nsproxy, pid_ns_for_children, ns).inum;

  if (pid_ns == PROC_PID_INIT_INO) {
    return 0;
  }

  u32 mnt_ns_id = BPF_CORE_READ(t, nsproxy, mnt_ns, ns).inum;

  bufs_t *string_p = get_buf(PATH_BUFFER);
  if (string_p == NULL)
    return 0;

  struct path p;
  p.dentry = dentry;
  p.mnt = BPF_CORE_READ(dir, mnt);

  if (!prepend_path(&p, string_p))
    return 0;
  // prepend_path_dentry(dentry, string_p, t);

  u32 *src_offset = get_buf_off(PATH_BUFFER);
  if (src_offset == NULL)
    return 0;

  bpf_printk("path_mknod mnt id - %u ! %s", mnt_ns_id,
             &string_p->buf[*src_offset]);

  return 0;
}


SEC("lsm/inode_link")
int BPF_PROG(inode_link, struct dentry *old_dentry, struct inode *inode_dir,
             struct dentry *new_dentry) {
  struct task_struct *t = (struct task_struct *)bpf_get_current_task();
  u32 pid_ns = BPF_CORE_READ(t, nsproxy, pid_ns_for_children, ns).inum;

  if (pid_ns == PROC_PID_INIT_INO) {
    return 0;
  }

  u32 mnt_ns_id = BPF_CORE_READ(t, nsproxy, mnt_ns, ns).inum;

  bufs_t *string_p = get_buf(PATH_BUFFER);
  if (string_p == NULL)
    return 0;

  prepend_path_dentry(new_dentry, string_p, t);

  u32 *src_offset = get_buf_off(PATH_BUFFER);
  if (src_offset == NULL)
    return 0;

  bpf_printk("inode_link mnt id - %u ! %s", mnt_ns_id,
             &string_p->buf[*src_offset]);

  return 0;
}

SEC("lsm/path_link")
int BPF_PROG(path_link, struct dentry *old_dentry, struct path *inode_dir,
             struct dentry *new_dentry) {
  struct task_struct *t = (struct task_struct *)bpf_get_current_task();
  u32 pid_ns = BPF_CORE_READ(t, nsproxy, pid_ns_for_children, ns).inum;

  if (pid_ns == PROC_PID_INIT_INO) {
    return 0;
  }

  u32 mnt_ns_id = BPF_CORE_READ(t, nsproxy, mnt_ns, ns).inum;

  bufs_t *string_p = get_buf(PATH_BUFFER);
  if (string_p == NULL)
    return 0;

  prepend_path_dentry(new_dentry, string_p, t);

  u32 *src_offset = get_buf_off(PATH_BUFFER);
  if (src_offset == NULL)
    return 0;

  bpf_printk("path_link mnt id - %u ! %s", mnt_ns_id,
             &string_p->buf[*src_offset]);

  return 0;
}

SEC("lsm/path_unlink")
int BPF_PROG(path_unlink, struct path *dir, struct dentry *dentry) {
  struct task_struct *t = (struct task_struct *)bpf_get_current_task();
  u32 pid_ns = BPF_CORE_READ(t, nsproxy, pid_ns_for_children, ns).inum;

  if (pid_ns == PROC_PID_INIT_INO) {
    return 0;
  }

  u32 mnt_ns_id = BPF_CORE_READ(t, nsproxy, mnt_ns, ns).inum;

  bufs_t *string_p = get_buf(PATH_BUFFER);
  if (string_p == NULL)
    return 0;

  struct path p;
  p.dentry = dentry;
  p.mnt = BPF_CORE_READ(dir, mnt);

  if (!prepend_path(&p, string_p))
    return 0;
  // prepend_path_dentry(dentry, string_p, t);

  u32 *src_offset = get_buf_off(PATH_BUFFER);
  if (src_offset == NULL)
    return 0;

  bpf_printk("path_unlink mnt id - %u ! %s", mnt_ns_id,
             &string_p->buf[*src_offset]);

  return 0;
}

SEC("lsm/inode_unlink")
int BPF_PROG(inode_unlink, struct inode *dir, struct dentry *dentry) {
  struct task_struct *t = (struct task_struct *)bpf_get_current_task();
  u32 pid_ns = BPF_CORE_READ(t, nsproxy, pid_ns_for_children, ns).inum;

  if (pid_ns == PROC_PID_INIT_INO) {
    return 0;
  }

  u32 mnt_ns_id = BPF_CORE_READ(t, nsproxy, mnt_ns, ns).inum;

  bufs_t *string_p = get_buf(PATH_BUFFER);
  if (string_p == NULL)
    return 0;

  prepend_path_dentry(dentry, string_p, t);

  u32 *src_offset = get_buf_off(PATH_BUFFER);
  if (src_offset == NULL)
    return 0;

  bpf_printk("inode_unlink mnt id - %u ! %s", mnt_ns_id,
             &string_p->buf[*src_offset]);

  return 0;
}