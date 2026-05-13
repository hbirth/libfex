/* SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-2-Clause) */
/*
 * fex/abi.h - wire-protocol definitions for the fusex filesystem.
 *
 * The bulk of the FUSE wire ABI now comes straight from the system's
 * <linux/fuse.h> (upstream UAPI). This header layers the fusex-only
 * extensions on top:
 *
 *   - Four extra opcodes the fusex kernel module emits
 *     (LOOKUP_ROOT/LOOKUPX/MKOBJX/SETSTATX). Upstream's `enum
 *     fuse_opcode` is closed, so these are #defines.
 *   - The matching message structs (fuse_entryx_out, fuse_setstatx_in,
 *     fuse_mkobjx_in).
 *   - The FUSE-over-io_uring notify INIT flag, which is fusex-only.
 *   - The FUSE-over-io_uring request/cmd UAPI (`fuse_uring_req_header`,
 *     `fuse_uring_cmd_req`, the cmd enum). These are upstream as of
 *     Linux 6.10 and present in modern kernel-headers packages; we
 *     supply them under an #ifndef guard so older toolchains still
 *     build.
 *
 * Everything else - the FUSE_* opcodes, FOPEN_*, INIT flags 1<<0
 * through 1<<42, fuse_in_header/fuse_out_header, fuse_statx,
 * fuse_kstatfs, fuse_read_in/fuse_write_in/etc., fuse_notify_code,
 * FUSE_DEV_IOC_* - comes from <linux/fuse.h>.
 *
 * This file is the C-compatible wire ABI; libfex hides it from C++
 * callers behind <fex/types.hpp>. It is included directly only inside
 * the library itself.
 */

#ifndef FEX_ABI_H
#define FEX_ABI_H

#include <linux/fuse.h>
#include <stdint.h>
#include <sys/ioctl.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---- versioning -------------------------------------------------------- */
/*
 * The fusex kernel module pins its handshake to this version pair. It
 * is independent of upstream FUSE_KERNEL_VERSION / FUSE_KERNEL_MINOR_VERSION;
 * the fusex variant declares its own.
 */
#define FEX_KERNEL_VERSION        7
#define FEX_KERNEL_MINOR_VERSION  46

/* ---- INIT flags (additions beyond upstream <linux/fuse.h>) ------------ */
/*
 * Upstream provides FUSE_OVER_IO_URING (1ULL<<41) and FUSE_REQUEST_TIMEOUT
 * (1ULL<<42). The notify-over-io_uring bit is a fusex-only extension.
 *
 * Older kernel-headers packages (pre-6.10) don't yet define
 * FUSE_OVER_IO_URING itself; supply the upstream value as a fallback so
 * libfex builds on those toolchains. The bit number is fixed by the
 * kernel UAPI and must match.
 */
#ifndef FUSE_OVER_IO_URING
#  define FUSE_OVER_IO_URING         (1ULL << 41)
#endif
#ifndef FUSE_OVER_IO_URING_NOTIFY
#  define FUSE_OVER_IO_URING_NOTIFY  (1ULL << 43)
#endif

/* ---- FUSE_DEV_IOC_SYNC_INIT (fallback for older linux/fuse.h) --------- */
/*
 * The sync-INIT ioctl flips /dev/fuse into the mode fusex requires.
 * Upstream added it alongside the io_uring transport; older headers
 * stop at FUSE_DEV_IOC_BACKING_CLOSE (= _IOW(229, 2, ...)). The number
 * (_IO(229, 3)) is fixed by the kernel.
 */
#ifndef FUSE_DEV_IOC_SYNC_INIT
#  define FUSE_DEV_IOC_SYNC_INIT     _IO(FUSE_DEV_IOC_MAGIC, 3)
#endif

/* ---- fusex-only opcodes ----------------------------------------------- */
/*
 * These extend `enum fuse_opcode` from <linux/fuse.h>. That enum is
 * closed (upstream stops at FUSE_COPY_FILE_RANGE_64 = 53), so we use
 * #defines to coexist. The values match the fusex kernel module's
 * private allocations and must stay in sync with it.
 */
#define FUSE_LOOKUP_ROOT  54
#define FUSE_LOOKUPX      55
#define FUSE_MKOBJX       56
#define FUSE_SETSTATX     58

/* ---- LOOKUPX / LOOKUP_ROOT reply -------------------------------------- */

#define FUSE_ENTRYX_NEGATIVE (1U << 0)

struct fuse_entryx_out {
    uint64_t nodeid;
    uint64_t entry_valid;
    uint32_t entry_valid_nsec;
    uint32_t flags;
    uint64_t spare;
};

/* ---- SETSTATX --------------------------------------------------------- */
/*
 * struct fuse_statx and struct fuse_statx_in / fuse_statx_out come from
 * <linux/fuse.h> (added upstream alongside FUSE_STATX = 52). Only the
 * SET variant is fusex-specific.
 */
struct fuse_setstatx_in {
    uint64_t fh;
    uint32_t flags;
    uint32_t reserved;
    struct fuse_statx stat;
};

/* ---- MKOBJX ----------------------------------------------------------- */

enum fuse_mkobjx_flags {
    FUSE_MKOBJX_TMPFILE = 1U << 0,
};

/*
 * Layout matches the kernel UAPI in <linux/fuse.h>: the small control
 * fields come first so they fit in the 128 B op_in slot of
 * fuse_uring_req_header; the embedded fuse_statx is sent by the kernel
 * as a separate in_arg in the payload region under io_uring transport.
 *
 * On the wire under io_uring:
 *   in_args[0] = offsetof(fuse_mkobjx_in, stat) bytes (control header)
 *   in_args[1] = struct fuse_statx
 *   in_args[2] = NUL-terminated name
 *   in_args[3] = link_body (S_IFLNK only)
 */
struct fuse_mkobjx_in {
    uint32_t namesize;
    uint32_t flags;
    uint64_t spare[7];
    struct fuse_statx stat;
};

/* ---- FUSE-over-io_uring UAPI (fallback for older linux/fuse.h) -------- */
/*
 * Linux 6.10+ ships these in <linux/fuse.h>; the guard skips this block
 * when the system header already defined them. The values are dictated
 * by the kernel and must match the upstream definitions exactly.
 */
#ifndef FUSE_URING_IN_OUT_HEADER_SZ

#define FUSE_URING_IN_OUT_HEADER_SZ 128
#define FUSE_URING_OP_IN_OUT_SZ     128

struct fuse_uring_ent_in_out {
    uint64_t flags;
    uint64_t commit_id;
    uint32_t payload_sz;
    uint32_t padding;
    uint64_t reserved;
};

struct fuse_uring_req_header {
    char in_out[FUSE_URING_IN_OUT_HEADER_SZ];
    char op_in [FUSE_URING_OP_IN_OUT_SZ];
    struct fuse_uring_ent_in_out ring_ent_in_out;
};

enum fuse_uring_cmd {
    FUSE_IO_URING_CMD_INVALID          = 0,
    FUSE_IO_URING_CMD_REGISTER         = 1,
    FUSE_IO_URING_CMD_COMMIT_AND_FETCH = 2,
};

struct fuse_uring_cmd_req {
    uint64_t flags;
    uint64_t commit_id;
    uint16_t qid;
    uint8_t  padding[6];
};

#endif  /* FUSE_URING_IN_OUT_HEADER_SZ */

#ifdef __cplusplus
}  /* extern "C" */
#endif

#endif  /* FEX_ABI_H */
