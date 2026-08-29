#ifndef KERNEL_DEFS_H
#define KERNEL_DEFS_H

/*
 * kernel_defs.h — Minimal kernel type definitions for Linux 5.13.x x86_64
 * non-CO-RE (no BTF/vmlinux.h). Replaces vmlinux.h for BPF programs.
 *
 * Inode layout config:
 *   KSHIELD_INODE_LAYOUT 3 (default) = CONFIG_FS_POSIX_ACL=y + CONFIG_SECURITY=y
 *   KSHIELD_INODE_LAYOUT 2           = CONFIG_FS_POSIX_ACL=n + CONFIG_SECURITY=y
 *   KSHIELD_INODE_LAYOUT 1           = CONFIG_FS_POSIX_ACL=n + CONFIG_SECURITY=n
 *
 * Override at compile time: clang ... -DKSHIELD_INODE_LAYOUT=1
 */

/* ── NULL pointer constant ──
 * Bare 0 is a null pointer constant in both C and C++.
 * Prevents system headers from redefining NULL as (void*)0, which is
 * a typed pointer in C++ and cannot implicitly convert to T* for T≠void. */
#ifndef NULL
#define NULL 0
#endif

/* ── Basic integer types ── */
typedef unsigned char      u8;
typedef unsigned short     u16;
typedef unsigned int       u32;
typedef unsigned long long u64;
typedef signed char        s8;
typedef signed short       s16;
typedef signed int         s32;
typedef signed long long   s64;

typedef unsigned long   size_t;    /* needed by my_string.h in C++ mode */
#ifndef __cplusplus
typedef unsigned char   bool;
#define true  1
#define false 0
#endif

typedef unsigned short  umode_t;
typedef int             pid_t;
typedef unsigned int    uid_t;
typedef unsigned int    dev_t;
typedef long long       loff_t;

typedef struct { unsigned int val; } kuid_t;
typedef struct { unsigned int val; } kgid_t;

/* ── timespec64 ── */
struct timespec64 {
    long long tv_sec;
    long      tv_nsec;
};

/* ── list / hash node types (used for sizeof padding) ── */
struct list_head      { struct list_head *next, *prev; };
struct hlist_node     { struct hlist_node *next, **pprev; };
struct hlist_bl_node  { struct hlist_bl_node *next, **pprev; };

/* ── struct qstr (dentry name, 5.13) ──
 *   [0] hash_len  u64  (union: u32 hash + u32 len)
 *   [8] name      const unsigned char*
 */
struct qstr {
    union {
        struct { u32 hash; u32 len; };
        u64 hash_len;
    };
    const unsigned char *name;
};

/* ── struct dentry (5.13, WITHOUT CONFIG_LOCKDEP) ──
 *   [0]  d_flags   u32
 *   [4]  d_seq     u32  (seqcount_spinlock_t without lockdep = just unsigned int)
 *   [8]  d_hash    hlist_bl_node  (16 bytes)
 *   [24] d_parent  struct dentry*
 *   [32] d_name    struct qstr    (16 bytes)
 *   [48] d_inode   struct inode*
 */
struct dentry {
    u32                   d_flags;
    u32                   d_seq;
    struct hlist_bl_node  d_hash;    /* 16 bytes */
    struct dentry        *d_parent;
    struct qstr           d_name;
    /* d_inode and rest omitted */
};

/* ── struct super_block (partial) ──
 *   [0]  s_list  list_head  (16 bytes)
 *   [16] s_dev   dev_t      (4 bytes)
 */
struct super_block {
    struct list_head s_list;   /* 16 bytes */
    dev_t            s_dev;
    /* rest omitted */
};

/* ── struct vfsmount (5.13, mnt_userns added in 5.11) ──
 *   [0]  mnt_root   struct dentry*
 *   [8]  mnt_sb     struct super_block*
 *   [16] mnt_flags  int
 *   [20] _pad       int
 *   [24] mnt_userns void*
 * total = 32 bytes
 */
struct vfsmount {
    struct dentry      *mnt_root;
    struct super_block *mnt_sb;
    int                 mnt_flags;
    int                 _pad;
    void               *mnt_userns;
};

/* ── struct mount (fs/mount.h, 5.13) ──
 *   [0]  mnt_hash        hlist_node  (16 bytes)
 *   [16] mnt_parent      struct mount*
 *   [24] mnt_mountpoint  struct dentry*
 *   [32] mnt             struct vfsmount (32 bytes, embedded)
 *
 * real_mount(vfsmnt) = container_of(vfsmnt, struct mount, mnt)
 *   → (char*)vfsmnt - 32
 *
 * From a vfsmnt pointer:
 *   mnt_parent     is at (char*)vfsmnt - 32 + 16 = (char*)vfsmnt - 16
 *   mnt_mountpoint is at (char*)vfsmnt - 32 + 24 = (char*)vfsmnt -  8
 *   mnt_root       is at (char*)vfsmnt + 0  (first field of embedded vfsmount)
 */
struct mount {
    struct hlist_node  mnt_hash;        /* 16 bytes */
    struct mount      *mnt_parent;
    struct dentry     *mnt_mountpoint;
    struct vfsmount    mnt;             /* embedded, 32 bytes */
    /* rest omitted */
};

/* ── struct path ── */
struct path {
    struct vfsmount *mnt;
    struct dentry   *dentry;
};

/* ── struct inode (5.13, layout selected by KSHIELD_INODE_LAYOUT) ──
 *
 * Stable prefix (all configs):
 *   [0]  i_mode   umode_t (2)
 *   [2]  i_opflags ushort (2)
 *   [4]  i_uid    kuid_t  (4)
 *   [8]  i_gid    kgid_t  (4)
 *   [12] i_flags  uint    (4)
 *
 * After that, use explicit byte offsets via bpf_probe_read_kernel.
 */
#ifndef KSHIELD_INODE_LAYOUT
#define KSHIELD_INODE_LAYOUT 3
#endif

#if KSHIELD_INODE_LAYOUT == 3   /* ACL=y SECURITY=y */
#define INODE_SB_OFFSET    40
#define INODE_INO_OFFSET   64
#define INODE_CTIME_OFFSET 120
#elif KSHIELD_INODE_LAYOUT == 2 /* ACL=n SECURITY=y */
#define INODE_SB_OFFSET    24
#define INODE_INO_OFFSET   48
#define INODE_CTIME_OFFSET 104
#else                            /* ACL=n SECURITY=n */
#define INODE_SB_OFFSET    24
#define INODE_INO_OFFSET   40
#define INODE_CTIME_OFFSET  96
#endif

struct inode {
    umode_t      i_mode;      /* [0] always first field */
    u16          i_opflags;
    kuid_t       i_uid;
    kgid_t       i_gid;
    u32          i_flags;
    /* fields beyond [12] accessed via explicit byte-offset probe_read */
};

/* ── struct file (5.13) ──
 *   [0]  f_u      union {llist_node; rcu_head} → 16 bytes
 *   [16] f_path   struct path                  → 16 bytes
 *   [32] f_inode  struct inode*
 */
struct file {
    u64          f_u[2];      /* 16-byte union placeholder */
    struct path  f_path;      /* [16] mnt @ +16, dentry @ +24 */
    struct inode *f_inode;    /* [32] */
    /* rest omitted */
};

/* ── struct filename (5.13) ──
 *   [0] name  const char*
 */
struct filename {
    const char *name;
    /* rest omitted */
};

/* ── struct ctl_table (partial) ──
 *   [0] procname  const char*
 *   [8] data      void*
 */
struct ctl_table {
    const char *procname;
    void       *data;
    /* rest omitted */
};

/* ── struct cred (partial, 5.13, no CONFIG_DEBUG_CREDENTIALS) ──
 *   [0] usage  int (atomic_t)
 *   [4] uid    kuid_t
 * NOTE: uid reading is replaced by bpf_get_current_uid_gid() in all hooks.
 */
struct cred {
    int    usage;
    kuid_t uid;
};

/* ── struct pt_regs (x86_64, Linux 5.13) — for PT_REGS_PARM1 / PT_REGS_RC ──
 * Member names use the r-prefixed style expected by older libbpf bpf_tracing.h:
 *   PT_REGS_PARM1 → rdi   PT_REGS_PARM2 → rsi   PT_REGS_PARM3 → rdx
 *   PT_REGS_PARM4 → rcx   PT_REGS_PARM5 → r8    PT_REGS_RC    → rax
 *   PT_REGS_IP    → rip   PT_REGS_SP/RET → rsp   PT_REGS_FP   → rbp
 * BPF_KPROBE extracts all parms even for 0-arg kprobes, so all must be present.
 */
struct pt_regs {
    unsigned long r15, r14, r13, r12, rbp, rbx;
    unsigned long r11, r10, r9,  r8;
    unsigned long rax, rcx, rdx, rsi, rdi;
    unsigned long orig_rax, rip;
    unsigned long cs, eflags, rsp, ss;
};

/* ── sched_process_exec tracepoint (fields we actually use: none) ── */
struct trace_event_raw_sched_process_exec {
    u64  _common[2]; /* skip common header */
    u32  __data_loc_filename;
    s32  pid;
    s32  old_pid;
};

/* ── S_IF* file mode constants (from vmlinux_flavors.h, kept here) ── */
#define S_IFMT   00170000
#define S_IFREG  0100000
#define S_IFDIR  0040000

/* ── BPF subsystem headers ──
 *
 * Poison-pill bpf_helpers.h and bpf_helper_defs.h: both assign (void*)N to
 * function pointer types, which is a GCC/Clang C extension but illegal in
 * C++.  We claim their include guards first, then provide equivalent
 * declarations using (rettype(*)(params))((unsigned long)N) — a C-style cast
 * from integer to function pointer that is valid in both C (as a GCC/Clang
 * extension) and C++ (treated as reinterpret_cast).
 */
#ifndef __BPF_HELPERS__
#define __BPF_HELPERS__
#endif
#ifndef __BPF_HELPER_DEFS__
#define __BPF_HELPER_DEFS__
#endif

/* Linux UAPI constants: BPF_MAP_TYPE_*, BPF_ANY, BPF_F_CURRENT_CPU,
 * struct bpf_raw_tracepoint_args, etc. */
#include <linux/bpf.h>

/* Map-definition helpers (normally from bpf_helpers.h) */
#ifndef SEC
#define SEC(name) __attribute__((section(name), used))
#endif
#ifndef __uint
#define __uint(name, val) int (*name)[val]
#endif
#ifndef __type
#  ifdef __cplusplus
#    define __type(name, val) __typeof__(val) *name
#  else
#    define __type(name, val) typeof(val) *name
#  endif
#endif

/* bpf_printk wraps bpf_trace_printk (helper #6) */
#ifndef bpf_printk
#define bpf_printk(fmt, ...)                    \
({                                              \
    static const char ____fmt[] = fmt;          \
    bpf_trace_printk(____fmt, sizeof(____fmt),  \
                     ##__VA_ARGS__);            \
})
#endif

/* ── BPF helper function pointer declarations (C++ safe) ──
 *
 * IDs match Linux 5.13 include/uapi/linux/bpf.h FN() macro ordering.
 * The __BPF_HELPER macro uses (ret(*)(params))((unsigned long)N):
 *   • In C:   GCC/Clang accept integer→function-pointer cast as extension.
 *   • In C++: C-style cast of integer→pointer = reinterpret_cast, which
 *             is explicitly allowed for pointer types (incl. function ptrs).
 */
#define __BPF_HELPER(ret, name, id, ...) \
    static ret (*name)(__VA_ARGS__) = (ret (*)(__VA_ARGS__))((unsigned long)(id))

__BPF_HELPER(void *,             bpf_map_lookup_elem,        1,  void *map, const void *key);
__BPF_HELPER(long,               bpf_map_update_elem,        2,  void *map, const void *key, const void *value, unsigned long long flags);
__BPF_HELPER(long,               bpf_map_delete_elem,        3,  void *map, const void *key);
__BPF_HELPER(long,               bpf_probe_read,             4,  void *dst, unsigned int size, const void *unsafe_ptr);
__BPF_HELPER(unsigned long long, bpf_ktime_get_ns,           5);
__BPF_HELPER(long,               bpf_trace_printk,           6,  const char *fmt, unsigned int fmt_size, ...);
__BPF_HELPER(unsigned long long, bpf_get_current_pid_tgid,  14);
__BPF_HELPER(unsigned long long, bpf_get_current_uid_gid,   15);
__BPF_HELPER(long,               bpf_get_current_comm,       16, void *buf, unsigned int size_of_buf);
__BPF_HELPER(long,               bpf_perf_event_output,      25, void *ctx, void *map, unsigned long long flags, void *data, unsigned long long size);
__BPF_HELPER(unsigned long long, bpf_get_current_task,       35);
__BPF_HELPER(long,               bpf_probe_read_str,         45, void *dst, unsigned int size, const void *unsafe_ptr);
__BPF_HELPER(long,               bpf_send_signal,           109, unsigned int sig);
__BPF_HELPER(long,               bpf_probe_read_kernel,     113, void *dst, unsigned int size, const void *unsafe_ptr);
__BPF_HELPER(long,               bpf_probe_read_kernel_str, 115, void *dst, unsigned int size, const void *unsafe_ptr);
__BPF_HELPER(long,               bpf_send_signal_thread,    117, unsigned int sig);

/* uint8_t used in maps.h callsite_bitmap value type */
typedef unsigned char uint8_t;

/* Forward declaration — pointer used by task.h helpers */
struct task_struct;

#endif /* KERNEL_DEFS_H */
