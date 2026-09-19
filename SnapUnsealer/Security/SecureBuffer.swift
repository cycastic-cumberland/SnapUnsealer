//
//  SecureBuffer.swift
//  SnapUnsealer
//

import Darwin
import Foundation

/// A heap buffer that is `mlock()`ed for its lifetime (best effort — macOS
/// can restrict this under sandboxing/memory pressure, so a lock failure is
/// logged and not treated as fatal, since this is defense-in-depth, not a
/// hard requirement the DR flow should ever be blocked by) and zeroed with
/// `memset_s` — never a plain Swift loop, which the compiler is legally
/// free to dead-store-eliminate as "writes nobody reads afterward", exactly
/// describing what wiping a secret looks like from its perspective.
final class SecureBuffer {
    private(set) var pointer: UnsafeMutableRawPointer
    let count: Int
    private var isLocked = false
    private var isZeroed = false

    init(count: Int) {
        self.count = count
        pointer = UnsafeMutableRawPointer.allocate(
            byteCount: max(count, 1),
            alignment: MemoryLayout<UInt8>.alignment
        )
        let result = mlock(pointer, count)
        isLocked = (result == 0)
        if !isLocked {
            let savedErrno = errno
            FileHandle.standardError.write(
                Data("SecureBuffer: mlock failed (errno \(savedErrno)) — continuing without page lock\n".utf8)
            )
        }
    }

    convenience init(copying data: Data) {
        self.init(count: data.count)
        data.withUnsafeBytes { raw in
            if let base = raw.baseAddress, raw.count > 0 {
                pointer.copyMemory(from: base, byteCount: raw.count)
            }
        }
    }

    /// A `Data` view over this buffer's own memory (no copy). Only valid
    /// for the lifetime of this `SecureBuffer` instance — do not let the
    /// returned `Data` outlive it.
    var dataNoCopy: Data {
        Data(bytesNoCopy: pointer, count: count, deallocator: .none)
    }

    func withUnsafeBytes<T>(_ body: (UnsafeRawBufferPointer) throws -> T) rethrows -> T {
        try body(UnsafeRawBufferPointer(start: pointer, count: count))
    }

    /// Explicitly zero now, ahead of deinit — call this as soon as the
    /// secret is no longer needed rather than waiting for ARC to get
    /// around to deallocating.
    func zero() {
        guard !isZeroed else { return }
        let result = memset_s(pointer, count, 0, count)
        if result != 0 {
            FileHandle.standardError.write(
                Data("SecureBuffer: memset_s returned \(result) — zeroing may be incomplete\n".utf8)
            )
        }
        isZeroed = true
    }

    deinit {
        zero()
        if isLocked {
            munlock(pointer, count)
        }
        pointer.deallocate()
    }
}
