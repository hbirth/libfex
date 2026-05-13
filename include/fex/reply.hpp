// SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only
//
// fex/reply.hpp - low-level reply helpers and the DirentWriter used by
// Filesystem::readdir() to fill the kernel's buffer.

#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

namespace fex {

// Writer passed into Filesystem::readdir(). Concrete implementation lives
// in the dispatcher; the daemon just calls `add()` until it returns false
// or it runs out of entries.
//
// Returns true if the entry was packed; false means the buffer is full
// and the daemon should stop (the failed entry must not be skipped on
// next readdir at offset+1).
class DirentWriter {
public:
    DirentWriter(std::span<std::byte> buf) noexcept
        : buf_(buf), pos_(0) {}

    // Pack one directory entry. `off` is the offset the kernel will pass
    // back on the next readdir to continue from after this entry. `type`
    // is a DT_* value from <dirent.h>.
    [[nodiscard]] bool add(std::string_view name,
                           std::uint64_t   ino,
                           std::uint64_t   off,
                           std::uint32_t   type) noexcept;

    // Bytes written so far; what the dispatcher will return to the kernel.
    std::size_t bytes_written() const noexcept { return pos_; }

    // True if no entry was ever added in this batch.
    bool empty() const noexcept { return pos_ == 0; }

private:
    std::span<std::byte> buf_;
    std::size_t          pos_;
};

}  // namespace fex
