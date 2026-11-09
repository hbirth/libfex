// SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only
//
// Internal header: io_uring worker. One RingWorker owns one ring, the
// entries of the FUSE queues assigned to it, and the thread that drives
// them. Session::run() instantiates `uring_threads` of them and divides
// the queues among them.
//
// Lives under namespace fex::detail because it is private to the
// implementation; the public API in <fex/session.hpp> never names it.

#pragma once

#include "session_impl.hpp"

#include <cstddef>
#include <cstdint>
#include <system_error>
#include <thread>
#include <utility>
#include <vector>

#include <liburing.h>
#include <sys/uio.h>

namespace fex::detail {

// User-data scheme: the bottom 32 bits hold the entry index (0..K-1
// for FUSE entries, K for the stop poll); we reserve the all-ones
// pattern for the stop poll. The kernel returns the same user_data we
// put in, so we can tell exactly which slot fired.
inline constexpr std::uint64_t kStopSentinel = 0xFFFFFFFFFFFFFFFFull;

// Bit 32 marks the zero copy read or write of the entry in the low bits,
// bit 33 a queue setup command (ADD_QUEUE, ADD_BUFPOOL).
inline constexpr std::uint64_t kZeroCopyBit = 1ull << 32;
inline constexpr std::uint64_t kSetupBit    = 1ull << 33;

class RingWorker {
public:
    RingWorker(Session::Impl& impl, std::vector<unsigned> qids, unsigned depth,
               std::size_t payload_bytes)
        : impl_(impl), qids_(std::move(qids)), depth_(depth),
          payload_bytes_(payload_bytes)
    {}

    ~RingWorker() { teardown(); }

    RingWorker(const RingWorker&)            = delete;
    RingWorker& operator=(const RingWorker&) = delete;
    RingWorker(RingWorker&&)                 = delete;
    RingWorker& operator=(RingWorker&&)      = delete;

    // Initialise the ring, allocate entry buffers, submit REGISTER for
    // each entry and the stop poll. The kernel will hold these SQEs
    // pending until requests arrive (REGISTER) or stop is signalled.
    std::error_code start();

    // Spawn the worker thread.
    void launch() { thread_ = std::thread([this]{ run(); }); }

    // Wait for the worker thread to exit. Stop is signalled centrally
    // via the shared stop_efd; the thread sees the poll completion,
    // breaks out, and returns.
    void join() { if (thread_.joinable()) thread_.join(); }

    // Surface any I/O error captured by the worker thread.
    std::error_code error() const noexcept { return ec_; }

private:
    struct Entry {
        // Without a buffer pool each entry has one contiguous region:
        //   [fuse_uring_req_header (288 B)] [payload area (payload_bytes_)]
        // With one, `buf` is only the header and the kernel picks the
        // payload area out of the queue's pool for each request.
        // The kernel writes the request into this region (header fields
        // + op_in + ent_in_out + payload); we write the reply by
        // overlaying fuse_out_header in in_out[] and putting reply
        // bytes in the payload area, then submitting COMMIT_AND_FETCH.
        std::byte*    buf       = nullptr;
        std::size_t   buf_len   = 0;
        std::uint64_t commit_id = 0;  // captured from each request
        unsigned      qid       = 0;  // FUSE queue this entry belongs to
        unsigned      q         = 0;  // its index in qids_ and pools_

        // Stable 2-segment iovec the kernel imports on every
        // REGISTER / COMMIT_AND_FETCH. fuse_uring_create_ring_ent()
        // requires exactly FUSE_URING_IOV_SEGS == 2 segments:
        //   iov[0] -> fuse_uring_req_header region (>= 288 B)
        //   iov[1] -> payload region (>= ring->max_payload_sz), empty
        //             with a buffer pool
        // Both segments are slices of `buf`; we keep them per-entry
        // so the address handed to the kernel stays valid until the
        // entry is torn down.
        struct iovec iov[2]{};

        // The zero copy transfer in flight, the reply waits for it.
        ::fuse_in_header zc_h{};
        bool             zc_write  = false;
        std::uint64_t    zc_offset = 0;
        IoTarget         zc_target;
    };

    // A queue's buffer pool.
    struct Pool {
        std::byte*  base = nullptr;
        std::size_t len  = 0;
        int         buf_index = -1;   // in the ring's buffer table, -1 if not registered
    };

    void run();
    void teardown() noexcept;

    // ADD_QUEUE and ADD_BUFPOOL for every queue, waiting for each.
    std::error_code setup_queues();
    std::error_code run_setup(bool bufpool);

    // The URING_CMD SQE for entry `i`, with the queue's pool index.
    void prep_cmd(io_uring_sqe* sqe, std::uint32_t i, std::uint32_t op) noexcept;

    // Build the REGISTER SQE for entry `i`. Used on initial arm.
    void prep_register(io_uring_sqe* sqe, std::uint32_t i) noexcept;

    // Build the COMMIT_AND_FETCH SQE for entry `i` carrying a reply.
    void prep_commit_and_fetch(io_uring_sqe* sqe, std::uint32_t i,
                               std::uint64_t commit_id) noexcept;

    // Commit the reply in entries_[i] and fetch the next request.
    bool commit(std::uint32_t i) noexcept;

    io_uring_sqe* get_sqe() noexcept;

    // The payload area of the request in entries_[i], nullptr if the
    // kernel reported a pool offset out of range.
    std::byte* payload_area(const Entry& e) noexcept;

    // Write fuse_out_header and ent_in_out.payload_sz of the reply.
    void set_reply(Entry& e, std::uint64_t unique, int neg_err,
                   std::size_t len) noexcept;

    // Process one request that's just landed in entries_[i].buf and write
    // the reply in place. False when the reply waits for a zero copy
    // transfer, which finish_zero_copy() completes.
    bool handle_one(std::uint32_t i) noexcept;

    bool start_zero_copy(std::uint32_t i) noexcept;
    void finish_zero_copy(std::uint32_t i, std::int32_t res) noexcept;

    // The buffer table slot the kernel puts entry `i`'s pages in.
    std::uint16_t zc_slot(std::uint32_t i) const noexcept {
        return static_cast<std::uint16_t>(pools_.size() + i);
    }

    Session::Impl&        impl_;
    std::vector<unsigned> qids_;
    unsigned              depth_;
    std::size_t           payload_bytes_;
    bool                  bufpool_   = false;
    bool                  zero_copy_ = false;
    std::vector<Pool>     pools_;

    // Body buffer for handler dispatch: reassembles [op_in (128B)] +
    // [payload (payload_sz)] into one contiguous region so the handlers
    // can treat "body" as a flat byte stream after fuse_in_header. One
    // per thread: this thread handles one request at a time.
    std::vector<std::byte> scratch_;

    io_uring             ring_{};
    bool                 ring_inited_ = false;
    std::vector<Entry>   entries_;
    std::thread          thread_;
    std::error_code      ec_;
};

}  // namespace fex::detail
