/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/*
 * fex/abi.h - userspace shim around the vendored kernel UAPI header
 * (fex/fuse_uapi.h). The vendored file is kept bit-for-bit identical
 * to include/uapi/linux/fuse.h in the fusex kernel branch; this shim
 * supplies what the kernel header expects from its includer:
 *
 *   - <sys/ioctl.h> provides _IO/_IOR/_IOW used by FUSE_DEV_IOC_* below.
 *   - The UAPI uses flexible array members in C++-incompatible ways
 *     (struct fuse_direntplus embeds struct fuse_dirent whose last
 *     member is `char name[]`), which trips -Wpedantic. We push/pop a
 *     local diagnostic suppression around the include rather than
 *     editing the vendored header.
 */

#ifndef FEX_ABI_H
#define FEX_ABI_H

#include <sys/ioctl.h>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
#include "fex/fuse_uapi.h"
#pragma GCC diagnostic pop

#endif  /* FEX_ABI_H */
