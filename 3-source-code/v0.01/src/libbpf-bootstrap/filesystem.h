#ifndef FILESYSTEM_H
#define FILESYSTEM_H

#include "maps.h"
#include "types.h"
#include "const.h"
#include "buffer.h"

#define statfunc static __always_inline

/* ─────────────────────────────────────────────
 * non-CO-RE filesystem helpers for Linux 5.13.x
 * All struct field reads use bpf_probe_read_kernel.
 * ───────────────────────────────────────────── */

/* get_buf is provided by buffer.h (included above) with the correct cast */

/* inode->i_mode : always at offset 0 */
statfunc unsigned short get_inode_mode_from_file(struct file *file)
{
    struct inode *inode = NULL;
    unsigned short mode = 0;
    bpf_probe_read_kernel(&inode, sizeof(inode), &file->f_inode);
    if (!inode)
        return 0;
    bpf_probe_read_kernel(&mode, sizeof(mode), &inode->i_mode);
    return mode;
}

/* inode->i_ino : offset depends on kernel config (see kernel_defs.h) */
statfunc unsigned long get_inode_nr_from_file(struct file *file)
{
    struct inode *inode = NULL;
    unsigned long ino = 0;
    bpf_probe_read_kernel(&inode, sizeof(inode), &file->f_inode);
    if (!inode)
        return 0;
    bpf_probe_read_kernel(&ino, sizeof(ino),
                          (char *)inode + INODE_INO_OFFSET);
    return ino;
}

/* inode->i_sb->s_dev : i_sb at INODE_SB_OFFSET, s_dev at offset 16 in sb */
statfunc dev_t get_dev_from_file(struct file *file)
{
    struct inode *inode = NULL;
    struct super_block *sb = NULL;
    dev_t dev = 0;
    bpf_probe_read_kernel(&inode, sizeof(inode), &file->f_inode);
    if (!inode)
        return 0;
    bpf_probe_read_kernel(&sb, sizeof(sb),
                          (char *)inode + INODE_SB_OFFSET);
    if (!sb)
        return 0;
    bpf_probe_read_kernel(&dev, sizeof(dev), &sb->s_dev);
    return dev;
}

/* inode->i_ctime : at INODE_CTIME_OFFSET (layout-dependent, see kernel_defs.h)
 * Kernel 5.13 always uses timespec64 i_ctime (not __i_ctime added in 6.6+).
 */
statfunc u64 get_ctime_nanosec_from_file(struct file *file)
{
    struct inode *inode = NULL;
    struct timespec64 ts = {};
    bpf_probe_read_kernel(&inode, sizeof(inode), &file->f_inode);
    if (!inode)
        return 0;
    bpf_probe_read_kernel(&ts, sizeof(ts),
                          (char *)inode + INODE_CTIME_OFFSET);
    if (ts.tv_sec < 0)
        return 0;
    return (u64)ts.tv_sec * 1000000000ULL + (u64)ts.tv_nsec;
}

statfunc file_id_t get_file_id(struct file *file)
{
    file_id_t id = {};
    if (!file)
        return id;
    id.ctime  = get_ctime_nanosec_from_file(file);
    id.device = get_dev_from_file(file);
    id.inode  = get_inode_nr_from_file(file);
    return id;
}

/* ── Path string construction via dentry walk (non-CO-RE) ──
 *
 * Struct offsets used (5.13 x86_64, no CONFIG_LOCKDEP):
 *   dentry->d_parent  : offset 24
 *   dentry->d_name    : offset 32 (struct qstr, 16 bytes)
 *     d_name.len      : offset 32+4 = 36 (u32)
 *     d_name.name     : offset 32+8 = 40 (const char*)
 *   vfsmount->mnt_root: offset  0
 *   In struct mount (mnt embedded at +32):
 *     mnt_parent      : (char*)vfsmnt - 16
 *     mnt_mountpoint  : (char*)vfsmnt -  8
 */
#define DENTRY_D_PARENT_OFF  24
#define DENTRY_D_NAME_OFF    32
#define DENTRY_DNAME_LEN_OFF 36   /* d_name.len  = d_name+4  */
#define DENTRY_DNAME_PTR_OFF 40   /* d_name.name = d_name+8  */
#define VFSMNT_MNT_ROOT_OFF   0
#define MOUNT_MNT_PARENT_FROM_VFSMNT  (-16)   /* (char*)vfsmnt + this */
#define MOUNT_MNT_MOUNTPOINT_FROM_VFSMNT (-8) /* (char*)vfsmnt + this */

statfunc void *get_path_str(struct path *path)
{
    buf_t *string_p = get_buf(STRING_BUF_IDX);
    if (!string_p)
        return NULL;

    char slash = '/';
    int  zero  = 0;

    struct vfsmount *vfsmnt  = NULL;
    struct dentry   *dentry  = NULL;

    /* Read f_path.mnt and f_path.dentry via probe_read */
    bpf_probe_read_kernel(&vfsmnt, sizeof(vfsmnt), &path->mnt);
    bpf_probe_read_kernel(&dentry, sizeof(dentry), &path->dentry);

    struct dentry   *mnt_parent_dentry = NULL;
    struct vfsmount *mnt_parent_vfsmnt = NULL;

    /* mnt_parent (struct mount*) is at (char*)vfsmnt - 16 */
    bpf_probe_read_kernel(&mnt_parent_vfsmnt, sizeof(mnt_parent_vfsmnt),
                          (char *)vfsmnt + MOUNT_MNT_PARENT_FROM_VFSMNT);

    u32 buf_off = (MAX_PERCPU_BUFSIZE >> 1);

#pragma unroll
    for (int i = 0; i < MAX_PATH_COMPONENTS; i++) {
        struct dentry *mnt_root   = NULL;
        struct dentry *d_parent   = NULL;
        unsigned int   d_name_len = 0;
        const char    *d_name_ptr = NULL;

        /* mnt_root = vfsmnt->mnt_root */
        bpf_probe_read_kernel(&mnt_root, sizeof(mnt_root),
                              (char *)vfsmnt + VFSMNT_MNT_ROOT_OFF);
        /* d_parent = dentry->d_parent */
        bpf_probe_read_kernel(&d_parent, sizeof(d_parent),
                              (char *)dentry + DENTRY_D_PARENT_OFF);

        if (dentry == mnt_root || dentry == d_parent) {
            if (dentry != mnt_root)
                break; /* escaped */

            if (vfsmnt != mnt_parent_vfsmnt) {
                /* cross mount point — climb up */
                /* mnt_mountpoint is at (char*)vfsmnt - 8 */
                bpf_probe_read_kernel(&dentry, sizeof(dentry),
                                      (char *)vfsmnt + MOUNT_MNT_MOUNTPOINT_FROM_VFSMNT);
                vfsmnt = mnt_parent_vfsmnt;
                bpf_probe_read_kernel(&mnt_parent_vfsmnt, sizeof(mnt_parent_vfsmnt),
                                      (char *)vfsmnt + MOUNT_MNT_PARENT_FROM_VFSMNT);
                continue;
            }
            break; /* global root */
        }

        /* d_name.len and d_name.name */
        bpf_probe_read_kernel(&d_name_len, sizeof(d_name_len),
                              (char *)dentry + DENTRY_DNAME_LEN_OFF);
        bpf_probe_read_kernel(&d_name_ptr, sizeof(d_name_ptr),
                              (char *)dentry + DENTRY_DNAME_PTR_OFF);

        unsigned int len = (d_name_len + 1) & (MAX_STRING_SIZE - 1);
        unsigned int off = buf_off - len;
        int sz = 0;

        if (off <= buf_off) {
            len = len & ((MAX_PERCPU_BUFSIZE >> 1) - 1);
            sz = bpf_probe_read_kernel_str(
                &string_p->buf[off & ((MAX_PERCPU_BUFSIZE >> 1) - 1)],
                len, d_name_ptr);
        } else {
            break;
        }

        if (sz > 1) {
            buf_off -= 1;
            bpf_probe_read_kernel(&string_p->buf[buf_off & (MAX_PERCPU_BUFSIZE - 1)],
                                  1, &slash);
            buf_off -= sz - 1;
        } else {
            break;
        }

        dentry = d_parent;
    }

    if (buf_off == (MAX_PERCPU_BUFSIZE >> 1)) {
        /* no path found — use dentry name directly */
        const char *d_name_ptr = NULL;
        bpf_probe_read_kernel(&d_name_ptr, sizeof(d_name_ptr),
                              (char *)dentry + DENTRY_DNAME_PTR_OFF);
        bpf_probe_read_kernel_str(&string_p->buf[0], MAX_STRING_SIZE, d_name_ptr);
    } else {
        buf_off -= 1;
        bpf_probe_read_kernel(&string_p->buf[buf_off & (MAX_PERCPU_BUFSIZE - 1)],
                              1, &slash);
        bpf_probe_read_kernel(&string_p->buf[(MAX_PERCPU_BUFSIZE >> 1) - 1],
                              1, &zero);
    }

    return &string_p->buf[buf_off];
}

statfunc void get_file_info(struct file *file, file_info_t *info)
{
    if (!file)
        return;
    info->id = get_file_id(file);
    /* Read f_path (mnt+dentry) via probe_read then call get_path_str */
    struct path p = {};
    bpf_probe_read_kernel(&p, sizeof(p), &file->f_path);
    info->pathname_p = (char *)get_path_str(&p);
}

#endif /* FILESYSTEM_H */
