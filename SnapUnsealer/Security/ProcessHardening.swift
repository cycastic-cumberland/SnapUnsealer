//
//  ProcessHardening.swift
//  SnapUnsealer
//

import Darwin

/// Process-wide defensive measures against secret material leaking to disk.
enum ProcessHardening {
    /// Disables core dumps for this process. A core dump is a full memory
    /// image written to disk in cleartext, which would bypass every other
    /// in-memory protection this app relies on.
    static func disableCoreDumps() {
        var limit = rlimit(rlim_cur: 0, rlim_max: 0)
        setrlimit(RLIMIT_CORE, &limit)
    }
}
