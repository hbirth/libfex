// SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only

#include "fex/reply.hpp"
#include "fex/abi.h"

#include <cstring>

namespace fex {

bool DirentWriter::add(std::string_view name,
                       std::uint64_t   ino,
                       std::uint64_t   off,
                       std::uint32_t   type) noexcept
{
    // Wire layout: struct fuse_dirent header, then `namelen` bytes
    // (no NUL), then padding up to 8-byte alignment. The kernel walks
    // this with FUSE_DIRENT_SIZE().
    const std::size_t name_off = sizeof(::fuse_dirent);
    const std::size_t raw      = name_off + name.size();
    const std::size_t padded   = (raw + 7u) & ~std::size_t{7u};

    if (padded > buf_.size() - pos_)
        return false;

    auto* d = reinterpret_cast<::fuse_dirent*>(buf_.data() + pos_);
    d->ino     = ino;
    d->off     = off;
    d->namelen = static_cast<std::uint32_t>(name.size());
    d->type    = type;
    std::memcpy(d->name, name.data(), name.size());
    // Zero the pad bytes so the wire is deterministic; the kernel
    // doesn't care but valgrind does.
    std::memset(buf_.data() + pos_ + raw, 0, padded - raw);

    pos_ += padded;
    return true;
}

}  // namespace fex
