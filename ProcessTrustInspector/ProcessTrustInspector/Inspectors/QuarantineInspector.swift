//
//  QuarantineInspector.swift
//  ProcessTrustInspector
//
//  Purpose:
//  Inspect quarantine extended-attribute metadata for an executable.
//

import Foundation
import Darwin

/// Inspector responsible for reading quarantine metadata from executable files.
final class QuarantineInspector {

    /// Determines whether quarantine metadata is present on an executable file.
    ///
    /// This inspects the presence of the `com.apple.quarantine` extended attribute.
    /// Absence of this attribute does not imply local origin or safety; metadata
    /// may be missing, stripped, or never applied depending on the execution path.
    ///
    /// - Parameter url: The executable file URL to inspect.
    /// - Returns: A `QuarantineStatus` representing observed presence, absence,
    ///            or an unknown/error condition.
    func getQuarantineStatus(for url: URL) -> QuarantineStatus {

        let pathstr = url.path
        var err: Int32

        // pass 1 for size and errors
        let size: Int = pathstr.withCString { cpath in
            getxattr(cpath, "com.apple.quarantine", nil, 0, 0, 0)
        }

        if size == -1 {
            err = errno
            if err == ENOATTR { return .absent }
            else { return .unknown(reason: "getxattr failed (errno \(err))") }
        }

        // pass 2 for the struct
        var data = Data(count: size)
        var size2: Int = 0

        pathstr.withCString { cpath in
            data.withUnsafeMutableBytes { buffer in
                size2 = getxattr(cpath, "com.apple.quarantine", buffer.baseAddress, size, 0, 0)
            }
        }

        if size2 == -1 {
            err = errno
            return .unknown(reason: "getxattr failed (errno \(err))")
        }

        let slice = data.prefix(size2)
        let qDetailsStr = String(data: slice, encoding: .utf8)

        guard let qDetailsStr else {
            return .present(details: QuarantineDetails(
                raw: "<non-utf8>",
                flags: nil,
                timestamp: nil,
                agentName: nil,
                eventIdentifier: nil
            ))
        }

        let qDetailsStruct = parseQuarantineXattr(qDetailsStr)
        return .present(details: qDetailsStruct)
    }
}
