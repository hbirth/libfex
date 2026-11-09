// SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only
//
// io_uring worker. Each RingWorker owns one io_uring instance and the
// entries of its FUSE queues. The thread's job is to keep `queue_depth`
// entries per queue armed (kernel-side) at all times: every time a CQE
// arrives the worker processes the request and immediately submits
// FUSE_IO_URING_CMD_COMMIT_AND_FETCH on the same SQE to post the reply
// AND re-arm for the next request. The only way out of the loop is the
// shared ring stop eventfd, which every ring has armed via
// IORING_OP_POLL_ADD, or the kernel ending the connection.
//
// A zero copy read or write is the exception: its bytes are in the
// caller's pages, which the kernel puts in this ring's buffer table. The
// worker moves them with READ_FIXED/WRITE_FIXED and commits the reply
// when that completes.

#include "uring_worker.hpp"

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <utility>

#include <poll.h>
#include <sys/mman.h>
#include <sys/prctl.h>

namespace fex::detail {

namespace {

constexpr std::uint64_t make_ud(std::uint32_t entry_idx) noexcept {
    return static_cast<std::uint64_t>(entry_idx);
}

}  // anonymous

void RingWorker::prep_cmd(io_uring_sqe* sqe, std::uint32_t i,
                          std::uint32_t op) noexcept
{
    auto& e = entries_[i];
    io_uring_prep_rw(IORING_OP_URING_CMD, sqe, impl_.dev_fd.get(),
                     nullptr, 0, 0);
    sqe->cmd_op = op;
    // fuse_uring_get_iovec_from_sqe() requires sqe->len ==
    // FUSE_URING_IOV_SEGS (= 2) and reads sqe->addr as a userspace
    // pointer to that iovec array (iov[0]=header, iov[1]=payload).
    // The kernel imports it via import_iovec() — no buffer
    // pre-registration is involved.
    sqe->addr = reinterpret_cast<std::uint64_t>(&e.iov[0]);
    sqe->len  = 2;

    // Every command of a queue with a registered pool names the pool.
    if (bufpool_ && pools_[e.q].buf_index >= 0) {
        sqe->uring_cmd_flags |= IORING_URING_CMD_FIXED;
        sqe->buf_index = static_cast<std::uint16_t>(pools_[e.q].buf_index);
    }

    auto* cmd = reinterpret_cast<::fuse_uring_cmd_req*>(&sqe->cmd);
    std::memset(cmd, 0, sizeof(*cmd));
    cmd->qid = static_cast<std::uint16_t>(e.qid);

    io_uring_sqe_set_data64(sqe, make_ud(i));
}

void RingWorker::prep_register(io_uring_sqe* sqe, std::uint32_t i) noexcept
{
    prep_cmd(sqe, i, FUSE_IO_URING_CMD_REGISTER);
    if (zero_copy_) {
        auto* cmd = reinterpret_cast<::fuse_uring_cmd_req*>(&sqe->cmd);
        cmd->ent_zero_copy_buf_index = zc_slot(i);
    }
}

void RingWorker::prep_commit_and_fetch(io_uring_sqe* sqe, std::uint32_t i,
                                       std::uint64_t commit_id) noexcept
{
    // Same 2-segment iovec convention as REGISTER.
    prep_cmd(sqe, i, FUSE_IO_URING_CMD_COMMIT_AND_FETCH);
    auto* cmd = reinterpret_cast<::fuse_uring_cmd_req*>(&sqe->cmd);
    cmd->commit_id = commit_id;
}

io_uring_sqe* RingWorker::get_sqe() noexcept
{
    io_uring_sqe* sqe = io_uring_get_sqe(&ring_);
    if (!sqe) {
        // SQ full. Submit pending and retry once.
        io_uring_submit(&ring_);
        sqe = io_uring_get_sqe(&ring_);
    }
    return sqe;
}

// One phase of queue setup: ADD_QUEUE or ADD_BUFPOOL for every queue. The
// commands complete inline, waiting for them keeps ADD_BUFPOOL after its
// ADD_QUEUE and both before the first REGISTER.
std::error_code RingWorker::run_setup(bool bufpool)
{
    for (unsigned q = 0; q < qids_.size(); ++q) {
        io_uring_sqe* sqe = get_sqe();
        if (!sqe) return {EAGAIN, std::system_category()};
        io_uring_prep_rw(IORING_OP_URING_CMD, sqe, impl_.dev_fd.get(),
                         nullptr, 0, 0);
        auto* cmd = reinterpret_cast<::fuse_uring_cmd_req*>(&sqe->cmd);
        std::memset(cmd, 0, sizeof(*cmd));
        cmd->qid = static_cast<std::uint16_t>(qids_[q]);
        if (!bufpool) {
            sqe->cmd_op = FUSE_IO_URING_CMD_ADD_QUEUE;
            cmd->flags  = zero_copy_ ? FUSE_URING_ZERO_COPY : 0;
        } else {
            const Pool& p = pools_[q];
            sqe->cmd_op = FUSE_IO_URING_CMD_ADD_BUFPOOL;
            cmd->bufpool.uaddr    = reinterpret_cast<std::uint64_t>(p.base);
            cmd->bufpool.len      = static_cast<std::uint32_t>(p.len);
            cmd->bufpool.buf_size = static_cast<std::uint32_t>(payload_bytes_);
            if (p.buf_index >= 0) {
                sqe->uring_cmd_flags |= IORING_URING_CMD_FIXED;
                sqe->buf_index = static_cast<std::uint16_t>(p.buf_index);
            }
        }
        io_uring_sqe_set_data64(sqe, kSetupBit | q);
    }

    int rc = io_uring_submit(&ring_);
    if (rc < 0)
        return {-rc, std::system_category()};

    std::error_code ec;
    for (unsigned n = 0; n < qids_.size(); ) {
        io_uring_cqe* cqe = nullptr;
        rc = io_uring_wait_cqe(&ring_, &cqe);
        if (rc == -EINTR) continue;
        if (rc < 0) return {-rc, std::system_category()};
        const std::uint64_t ud  = io_uring_cqe_get_data64(cqe);
        const std::int32_t  res = cqe->res;
        io_uring_cqe_seen(&ring_, cqe);
        // The stop poll can't fire before the workers launch.
        if (!(ud & kSetupBit))
            continue;
        ++n;
        if (res < 0 && !ec) {
            std::fprintf(stderr, "fex worker[qid=%u]: %s failed: %s\n",
                         qids_[static_cast<unsigned>(ud & 0xffffffffu)],
                         bufpool ? "ADD_BUFPOOL" : "ADD_QUEUE", ::strerror(-res));
            ec = {-res, std::system_category()};
        }
    }
    return ec;
}

std::error_code RingWorker::setup_queues()
{
    if (auto ec = run_setup(false))
        return ec;
    return run_setup(true);
}

std::error_code RingWorker::start()
{
    bufpool_   = impl_.opts.uring_bufpool_buffers > 0;
    zero_copy_ = impl_.opts.uring_zero_copy;
    // The kernel zero-copies only on queues with a pool.
    if (zero_copy_ && !bufpool_)
        return {EINVAL, std::system_category()};

    // Pre-allocate all entry buffers up front; if any allocation
    // fails we tear down everything (entries_ is owning).
    entries_.resize(qids_.size() * depth_);
    for (std::size_t i = 0; i < entries_.size(); ++i) {
        entries_[i].q   = static_cast<unsigned>(i / depth_);
        entries_[i].qid = qids_[i / depth_];
    }
    const std::size_t entry_payload = bufpool_ ? 0 : payload_bytes_;
    const std::size_t buf_len = sizeof(::fuse_uring_req_header) + entry_payload;
    for (auto& e : entries_) {
        // Page-align so the kernel's copy_to_user paths stay happy on
        // large transfers. We over-allocate by one page for simplicity
        // (a posix_memalign would be tighter; mmap keeps it portable).
        void* p = ::mmap(nullptr, buf_len, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p == MAP_FAILED)
            return {errno, std::system_category()};
        e.buf     = static_cast<std::byte*>(p);
        e.buf_len = buf_len;
        // iov[0] = header, iov[1] = payload (slices of `buf`). A queue
        // on a pool registers no payload.
        e.iov[0].iov_base = e.buf;
        e.iov[0].iov_len  = sizeof(::fuse_uring_req_header);
        e.iov[1].iov_base = entry_payload ? e.buf + sizeof(::fuse_uring_req_header)
                                          : nullptr;
        e.iov[1].iov_len  = entry_payload;
    }

    if (bufpool_) {
        const std::size_t pool_len =
            std::size_t{impl_.opts.uring_bufpool_buffers} * payload_bytes_;
        // fuse_uring_cmd_req.bufpool.len is 32 bits.
        if (pool_len > UINT32_MAX || payload_bytes_ > UINT32_MAX)
            return {EINVAL, std::system_category()};
        pools_.resize(qids_.size());
        for (auto& pool : pools_) {
            void* p = ::mmap(nullptr, pool_len, PROT_READ | PROT_WRITE,
                             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            if (p == MAP_FAILED)
                return {errno, std::system_category()};
            pool.base = static_cast<std::byte*>(p);
            pool.len  = pool_len;
        }
    }

    // 128B op_in fits in any case; the variable part is the trailing
    // payload.
    scratch_.resize(FUSE_URING_OP_IN_OUT_SZ + payload_bytes_);

    // FUSE-over-io_uring requires both SQE128 and CQE32:
    //   - SQE128: fuse_uring_cmd_req lives in the SQE cmd area, which
    //     only has 16 bytes in a normal SQE.
    //   - CQE32:  the kernel's fuse_uring_register() rejects with
    //     -EINVAL if IO_URING_F_CQE32 isn't set on the cmd.
    // Every entry can have a completion outstanding, plus the stop poll.
    // The REGISTERs are submitted in batches if the SQ is smaller.
    const unsigned total = static_cast<unsigned>(entries_.size()) + 1;
    const unsigned ring_entries = std::min(total, 4096u);
    io_uring_params params{};
    params.flags = IORING_SETUP_SQE128 | IORING_SETUP_CQE32 |
                   IORING_SETUP_CQSIZE | IORING_SETUP_CLAMP;
    params.cq_entries = std::max(total, 2 * ring_entries);
    int rc = io_uring_queue_init_params(ring_entries, &ring_, &params);
    if (rc < 0)
        return {-rc, std::system_category()};
    ring_inited_ = true;

    // Buffer table: the pools first, then one empty slot per entry where
    // the kernel puts the pages of a zero copy request.
    if (bufpool_) {
        const unsigned slots = static_cast<unsigned>(pools_.size()) +
            (zero_copy_ ? static_cast<unsigned>(entries_.size()) : 0u);
        if (slots > UINT16_MAX + 1u)
            return {EINVAL, std::system_category()};
        rc = io_uring_register_buffers_sparse(&ring_, slots);
        if (rc < 0 && zero_copy_)
            return {-rc, std::system_category()};
        for (unsigned q = 0; rc >= 0 && q < pools_.size(); ++q) {
            struct iovec iov{pools_[q].base, pools_[q].len};
            // Best effort, RLIMIT_MEMLOCK may not allow it. The kernel
            // then pins the pool on every request instead.
            if (io_uring_register_buffers_update_tag(&ring_, q, &iov,
                                                     nullptr, 1) == 1)
                pools_[q].buf_index = static_cast<int>(q);
        }
    }

    // Submit one POLL_ADD on the stop eventfd, tagged with the stop
    // sentinel. The kernel never completes this until run() writes
    // to the eventfd, at which point every ring's poll fires.
    {
        io_uring_sqe* sqe = io_uring_get_sqe(&ring_);
        if (!sqe) return {EAGAIN, std::system_category()};
        io_uring_prep_poll_add(sqe, impl_.ring_stop_efd.get(), POLLIN);
        io_uring_sqe_set_data64(sqe, kStopSentinel);
    }

    if (bufpool_) {
        if (auto ec = setup_queues())
            return ec;
    }

    // REGISTER each entry. The kernel keeps these pending until a
    // request shows up on this queue, then completes the matching SQE
    // with the request laid out in the entry buffer.
    for (std::uint32_t i = 0; i < entries_.size(); ++i) {
        io_uring_sqe* sqe = get_sqe();
        if (!sqe) return {EAGAIN, std::system_category()};
        prep_register(sqe, i);
    }

    rc = io_uring_submit(&ring_);
    if (rc < 0)
        return {-rc, std::system_category()};

    return {};
}

std::byte* RingWorker::payload_area(const Entry& e) noexcept
{
    if (!bufpool_)
        return e.buf + sizeof(::fuse_uring_req_header);

    // Only valid if the kernel gave the request a buffer, which it does
    // when there is data either way. The handlers write the payload only
    // for replies that have one.
    const auto* req = reinterpret_cast<const ::fuse_uring_req_header*>(e.buf);
    const Pool& p = pools_[e.q];
    const std::size_t off = req->ring_ent_in_out.offset;
    if (off > p.len || p.len - off < payload_bytes_)
        return nullptr;
    return p.base + off;
}

void RingWorker::set_reply(Entry& e, std::uint64_t unique, int neg_err,
                           std::size_t len) noexcept
{
    // Write the reply header on top of the in_out region.
    auto* req  = reinterpret_cast<::fuse_uring_req_header*>(e.buf);
    auto* outh = reinterpret_cast<::fuse_out_header*>(req->in_out);
    if (neg_err)
        len = 0;
    outh->unique = unique;
    outh->error  = neg_err;
    outh->len    = static_cast<std::uint32_t>(sizeof(::fuse_out_header) + len);
    req->ring_ent_in_out.payload_sz = static_cast<std::uint32_t>(len);
}

bool RingWorker::handle_one(std::uint32_t i) noexcept
{
    Entry& e = entries_[i];
    auto* req = reinterpret_cast<::fuse_uring_req_header*>(e.buf);

    // Kernel request layout:
    //   in_out[0..40]              -> fuse_in_header
    //   op_in[0..in_args[0].size]  -> first in_arg
    //   ring_ent_in_out.payload_sz -> in_args[1..] in the payload area
    e.commit_id = req->ring_ent_in_out.commit_id;
    const std::uint32_t payload_sz = req->ring_ent_in_out.payload_sz;

    const auto* h = reinterpret_cast<const ::fuse_in_header*>(req->in_out);
    ::fuse_in_header h_copy = *h;  // reply clobbers in_out

    if (req->ring_ent_in_out.flags & FUSE_URING_ENT_ZERO_COPY) {
        e.zc_h = h_copy;
        return !start_zero_copy(i);
    }

    std::byte* payload = payload_area(e);

    // in_args[0].size is derivable from the request — it's whatever's
    // left after the header and the payload. Assemble the body as one
    // contiguous [in_args[0]][in_args[1..]] span; handlers then index
    // past in_args[0] using sizeof(its first in_arg struct).
    const std::size_t first_arg_sz =
        h_copy.len >= sizeof(::fuse_in_header) + payload_sz
            ? h_copy.len - sizeof(::fuse_in_header) - payload_sz
            : 0u;
    const std::size_t body_len = first_arg_sz + payload_sz;

    if (first_arg_sz > FUSE_URING_OP_IN_OUT_SZ ||
        body_len > scratch_.size() || (payload_sz && !payload)) {
        set_reply(e, h_copy.unique, -EIO, 0);
        return true;
    }

    if (first_arg_sz)
        std::memcpy(scratch_.data(), req->op_in, first_arg_sz);
    if (payload_sz)
        std::memcpy(scratch_.data() + first_arg_sz, payload, payload_sz);

    Replier r;
    r.out    = payload;
    r.cap    = payload ? payload_bytes_ : 0;
    r.unique = h_copy.unique;

    impl_.dispatch(h_copy, scratch_.data(), body_len, r);

    set_reply(e, r.unique, r.neg_err, r.len);
    return true;
}

// Starts the transfer of a zero copy READ or WRITE. False when the reply,
// an error, is already in place.
bool RingWorker::start_zero_copy(std::uint32_t i) noexcept
{
    Entry& e = entries_[i];
    const auto* req = reinterpret_cast<const ::fuse_uring_req_header*>(e.buf);
    const ::fuse_in_header& h = e.zc_h;
    const bool write = h.opcode == FUSE_WRITE;
    std::uint64_t offset;
    std::size_t len;

    // Only these two are zero-copied. The op header is the only argument
    // that isn't the pages, fusex sends no extensions.
    if ((h.opcode != FUSE_READ && !write) || h.total_extlen) {
        set_reply(e, h.unique, -EIO, 0);
        return false;
    }
    if (write) {
        ::fuse_write_in in;
        std::memcpy(&in, req->op_in, sizeof(in));
        offset = in.offset;
        len    = in.size;
    } else {
        ::fuse_read_in in;
        std::memcpy(&in, req->op_in, sizeof(in));
        offset = in.offset;
        len    = in.size;
    }

    auto target = impl_.fs->io_target(Session::Impl::make_ctx(h),
                                      static_cast<NodeId>(h.nodeid), write,
                                      offset, len);
    if (!target) {
        set_reply(e, h.unique, neg_errno(target.error()), 0);
        return false;
    }

    io_uring_sqe* sqe = get_sqe();
    if (!sqe) {
        set_reply(e, h.unique, -EAGAIN, 0);
        return false;
    }
    // The kernel's buffer starts at the first byte of the request's data.
    if (write)
        io_uring_prep_write_fixed(sqe, target->fd, nullptr,
                                  static_cast<unsigned>(len), target->offset,
                                  zc_slot(i));
    else
        io_uring_prep_read_fixed(sqe, target->fd, nullptr,
                                 static_cast<unsigned>(len), target->offset,
                                 zc_slot(i));
    io_uring_sqe_set_data64(sqe, kZeroCopyBit | make_ud(i));

    e.zc_write  = write;
    e.zc_offset = offset;
    e.zc_target = std::move(*target);
    return true;
}

void RingWorker::finish_zero_copy(std::uint32_t i, std::int32_t res) noexcept
{
    Entry& e = entries_[i];
    const ::fuse_in_header& h = e.zc_h;
    std::expected<std::size_t, Errc> result;

    if (res < 0)
        result = std::unexpected{errc_from_errno(-res)};
    else
        result = static_cast<std::size_t>(res);
    impl_.fs->io_done(Session::Impl::make_ctx(h), static_cast<NodeId>(h.nodeid),
                      e.zc_write, e.zc_offset, result, e.zc_target);
    e.zc_target = {};

    if (res < 0) {
        set_reply(e, h.unique, res, 0);
        return;
    }
    if (!e.zc_write) {
        // The data is in the caller's pages already.
        set_reply(e, h.unique, 0, static_cast<std::size_t>(res));
        return;
    }

    // fuse_write_out goes through the pool buffer.
    std::byte* payload = payload_area(e);
    if (!payload) {
        set_reply(e, h.unique, -EIO, 0);
        return;
    }
    ::fuse_write_out out{};
    out.size = static_cast<std::uint32_t>(res);
    std::memcpy(payload, &out, sizeof(out));
    set_reply(e, h.unique, 0, sizeof(out));
}

bool RingWorker::commit(std::uint32_t i) noexcept
{
    // Ship the reply and re-arm the slot.
    io_uring_sqe* sqe = get_sqe();
    if (!sqe) {
        ec_ = {EAGAIN, std::system_category()};
        return false;
    }
    prep_commit_and_fetch(sqe, i, entries_[i].commit_id);
    int sr = io_uring_submit(&ring_);
    if (sr < 0) {
        ec_ = {-sr, std::system_category()};
        return false;
    }
    return true;
}

void RingWorker::run()
{
    // Requests for this mount can depend on this thread making progress, so
    // its memory allocations must not reclaim from filesystems or wait for
    // dirty pages. Needs CAP_SYS_RESOURCE, which a root daemon has.
    (void)::prctl(PR_SET_IO_FLUSHER, 1, 0, 0, 0);

    bool stop = false;
    while (!stop) {
        io_uring_cqe* cqe = nullptr;
        int rc = io_uring_wait_cqe(&ring_, &cqe);
        if (rc < 0) {
            if (rc == -EINTR) continue;
            ec_ = {-rc, std::system_category()};
            break;
        }

        const std::uint64_t ud = io_uring_cqe_get_data64(cqe);
        const std::int32_t  res = cqe->res;
        io_uring_cqe_seen(&ring_, cqe);

        if (ud == kStopSentinel) {
            // Stop signalled. We deliberately do NOT try to drain or
            // commit any in-flight entries: the kernel side cancels
            // pending URING_CMDs when the device closes, and our
            // teardown closes the ring. Any half-built replies are
            // discarded by the kernel along with the entries.
            stop = true;
            break;
        }

        const auto idx = static_cast<std::uint32_t>(ud);
        if (idx >= entries_.size()) {
            // Shouldn't happen; if it does, log via ec_ and continue.
            ec_ = {EINVAL, std::system_category()};
            continue;
        }

        if (ud & kZeroCopyBit) {
            // The transfer of a zero copy request ended, reply now.
            finish_zero_copy(idx, res);
            if (!commit(idx))
                break;
            continue;
        }

        if (res < 0) {
            // The filesystem is being torn down, or the connection was
            // aborted, or this task's commands were cancelled.
            if (res == -ENOTCONN || res == -ENODEV ||
                res == -ECONNABORTED || res == -ECANCELED) {
                stop = true;
                break;
            }
            if (res == -EINTR) {
                // Re-arm the slot with another REGISTER.
                io_uring_sqe* sqe = io_uring_get_sqe(&ring_);
                if (sqe) { prep_register(sqe, idx); io_uring_submit(&ring_); }
                continue;
            }
            // Other errors: surface and stop.
            std::fprintf(stderr,
                "fex worker[qid=%u]: CQE res=%d (%s) for entry idx=%u\n",
                entries_[idx].qid, res, ::strerror(-res), idx);
            ec_ = {-res, std::system_category()};
            stop = true;
            break;
        }

        // Successful fetch — a request landed in entries_[idx]. Run it
        // and immediately submit COMMIT_AND_FETCH to ship the reply
        // and re-arm the slot, unless a zero copy transfer has to end
        // first.
        if (!handle_one(idx)) {
            if (int sr = io_uring_submit(&ring_); sr < 0) {
                ec_ = {-sr, std::system_category()};
                break;
            }
            continue;
        }
        if (!commit(idx))
            break;
    }

    // A worker that gave up can't serve its queues any more, and nothing
    // else tells run(). The kernel would wait for it forever.
    impl_.worker_exited();
}

void RingWorker::teardown() noexcept
{
    if (ring_inited_) {
        io_uring_queue_exit(&ring_);
        ring_inited_ = false;
    }
    for (auto& e : entries_) {
        if (e.buf) {
            ::munmap(e.buf, e.buf_len);
            e.buf = nullptr;
        }
    }
    entries_.clear();
    for (auto& p : pools_) {
        if (p.base)
            ::munmap(p.base, p.len);
    }
    pools_.clear();
}

}  // namespace fex::detail
