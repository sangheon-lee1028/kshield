#ifndef VMLINUX_FLAVORS_H
#define VMLINUX_FLAVORS_H

/*
 * Kernel 5.13 uses struct timespec64 i_ctime directly.
 * The __i_ctime / inode___older_v611 variant exists only in kernel >= 6.6.
 * bpf_core_field_exists() checks are removed in this non-CO-RE version.
 * All S_IF* constants now live in kernel_defs.h.
 */

#endif
