//! Simple spinlock for platforms without std.Thread.Mutex.
//! Uses atomic compare-and-swap. Busy-waits, but uncontended fast path is 1 CAS.

const std = @import("std");

pub const Spinlock = struct {
    flag: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),

    pub fn lock(self: *Spinlock) void {
        while (self.flag.swap(1, .acquire) != 0) {
            while (self.flag.load(.monotonic) != 0) {
                std.atomic.spinLoopHint();
            }
        }
    }

    pub fn unlock(self: *Spinlock) void {
        self.flag.store(0, .release);
    }
};
