// SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only
//
// fex/session.hpp - high-level entry point.
//
// A Session owns:
//   - the open /dev/fuse fd,
//   - the mount (set up via fsopen/fsconfig/fsmount/move_mount),
//   - a pool of per-queue io_uring rings that carry every post-INIT
//     request and reply.
//
// Transport: every request and reply travels over FUSE-over-io_uring
// (`IORING_OP_URING_CMD` with `FUSE_IO_URING_CMD_REGISTER` /
// `FUSE_IO_URING_CMD_COMMIT_AND_FETCH`), including the mount-time
// handshake (INIT / LOOKUP_ROOT / STATX). The daemon registers ring
// entries between `fsconfig(SET_FD)` and `fsconfig(CMD_CREATE)`, and
// the kernel's `fusex_fill_super` then routes INIT through the rings
// like any other request. `/dev/fuse` is the channel fd that carries
// the URING_CMD opcodes; no `read()`/`writev()` traffic ever happens
// on it.
//
// Concurrency: there are `uring_queues` worker threads, each owning
// one ring of `uring_queue_depth` entries. Up to
// `uring_queues * uring_queue_depth` filesystem callbacks may run
// concurrently — `Filesystem` implementations must be thread-safe.
//
// Typical use:
//
//     MyFilesystem fs{...};
//     fex::Session s(fex::SessionOptions{
//         .mountpoint = "/mnt/myfs",
//         .fsname     = "myfs",
//     });
//     s.run(fs);                  // blocks until unmount
//
// `run()` is the foreground entry; `stop()` from another thread (or a
// signal handler) writes to an internal eventfd that every ring polls,
// unblocking the workers cleanly.

#pragma once

#include "filesystem.hpp"

#include <expected>
#include <memory>
#include <string>
#include <system_error>

namespace fex {

// Owning RAII wrapper for a Unix fd. Exposed because callers occasionally
// want to peek at the dev fd (e.g. to clone it for an io_uring channel
// once that support lands).
class UniqueFd {
public:
    UniqueFd() noexcept = default;
    explicit UniqueFd(int fd) noexcept : fd_(fd) {}
    ~UniqueFd();

    UniqueFd(const UniqueFd&)            = delete;
    UniqueFd& operator=(const UniqueFd&) = delete;

    UniqueFd(UniqueFd&& o) noexcept : fd_(o.fd_) { o.fd_ = -1; }
    UniqueFd& operator=(UniqueFd&& o) noexcept;

    int  get() const noexcept { return fd_; }
    int  release() noexcept   { int r = fd_; fd_ = -1; return r; }
    bool valid() const noexcept { return fd_ >= 0; }
    void reset(int fd = -1) noexcept;

private:
    int fd_ = -1;
};

struct SessionOptions {
    // Where to mount. Must already exist and be a directory.
    std::string mountpoint;

    // Optional human-readable source label (shows in /proc/self/mountinfo).
    std::string fsname = "fex";

    // Mount the FS read-only.
    bool read_only = false;

    // Allow non-root users to access the mount (`-o allow_other` in
    // libfuse parlance). Requires user_allow_other in fuse.conf for
    // unprivileged daemons.
    bool allow_other = false;

    // If non-empty, an already-open fd to /dev/fuse; the Session takes
    // ownership. If <0 (default), the Session opens /dev/fuse itself.
    // Useful for test harnesses that pre-clone fds.
    int  dev_fd = -1;

    // ---- io_uring transport ------------------------------------------
    // Each ring is polled by its own worker thread; this is how the
    // session achieves multi-threaded dispatch. Total in-flight
    // capacity is `uring_queues * uring_queue_depth`.

    // Number of FUSE-over-io_uring queues (rings). 0 means "pick
    // `std::thread::hardware_concurrency()`, clamped to [1, 32]".
    unsigned uring_queues = 0;

    // Per-ring queue depth. The kernel keeps this many request entries
    // in flight per queue. Each entry pre-allocates a request buffer of
    // size `uring_payload_bytes + sizeof(fuse_uring_req_header)`, so
    // total RSS for the rings is roughly
    // `uring_queues * uring_queue_depth * uring_payload_bytes`.
    unsigned uring_queue_depth = 32;

    // Per-entry payload area. Caps the largest single READ/WRITE the
    // daemon will accept. The INIT handler advertises max_pages such
    // that one request fits in this many bytes.
    std::size_t uring_payload_bytes = 1u << 20;   // 1 MiB
};

class Session {
public:
    explicit Session(SessionOptions opts);
    ~Session();

    Session(const Session&)            = delete;
    Session& operator=(const Session&) = delete;

    // Mount, run, and join the request workers. Returns when:
    //  - the kernel closes the device (umount), or
    //  - stop() was called, or
    //  - an unrecoverable I/O error occurred.
    //
    // On entry, performs sync-INIT: ioctl(FUSE_DEV_IOC_SYNC_INIT),
    // mounts via fsopen/fsconfig/fsmount, services the kernel's
    // INIT/LOOKUP_ROOT/STATX handshake on this thread, then spawns
    // `opts.uring_queues` ring workers and blocks until they all
    // exit. Filesystem callbacks may run concurrently on any worker
    // thread after the handshake completes — implementations must be
    // thread-safe.
    //
    // Errors during the handshake abort run() with the mount torn down.
    std::error_code run(Filesystem& fs);

    // Asynchronous request to wind down. Safe to call from a signal
    // handler — it's just an atomic store and an eventfd write that
    // every ring worker is polling on.
    void stop() noexcept;

    // Inspect the dev fd (e.g., for diagnostics, or to share with an
    // out-of-band channel). Workers do not read from it after the
    // mount handshake completes — they own their rings.
    int device_fd() const noexcept;

    // Defined in session.cpp. The struct is exposed (but not its
    // members) because the in-TU RingWorker holds a reference.
    struct Impl;

private:
    std::unique_ptr<Impl> impl_;
};

// Convenience: open /dev/fuse and perform the sync-INIT ioctl. Useful
// when callers want to do the mount themselves and just need a properly
// prepared device fd.
std::expected<UniqueFd, std::error_code> open_fex_device();

}  // namespace fex
