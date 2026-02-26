//
//  CStringDecoders.swift
//  ProcessTrustInspector
//
//  Small utilities for decoding C strings returned by Darwin APIs.
//
//  These helpers sit at the boundary between C and Swift.
//  Use them when:
//  - A C API writes into a `[CChar]` buffer (e.g. `proc_pidpath`).
//  - A C struct exposes a fixed-size char array imported as a tuple
//    (e.g. `proc_bsdinfo.pbi_comm`).
//
//  They intentionally do one thing: safely convert null-terminated
//  C string data into Swift `String` values without guessing.
//
//

   /// Decode a fixed-size C char array field (imported from C as a tuple)
    /// into a Swift `String`.
    ///
    /// Use this when reading string fields embedded in C structs,
    /// like `proc_bsdinfo.pbi_comm` or `pbi_name`.
    ///
    /// Unlike `decodeCStringBuffer`, this is for struct fields with
    /// a compile-time fixed size — not for `[CChar]` buffers
    /// allocated and passed into a C function.
    func decodeFixedCString<T>(_ field: T) -> String? {
        // Make a mutable copy so we can take a stable address for withUnsafeBytes.
        var copy = field

        return withUnsafeBytes(of: &copy) { rawBuffer -> String? in
            // Treat it as bytes, find the first NUL terminator, then UTF-8 decode.
            guard let nulIndex = rawBuffer.firstIndex(of: 0) else {
                // No terminator found; treat as invalid/unknown rather than guessing.
                return nil
            }

            let bytes = rawBuffer.prefix(upTo: nulIndex)
            return String(decoding: bytes, as: UTF8.self)
        }
    }

    /// Decode a null-terminated C string stored in a mutable `[CChar]` buffer
    /// (e.g. filled by `proc_pidpath`) into a Swift `String`.
    ///
    /// Use this when you’ve called a C API that writes into a buffer you allocated
    /// and you need to convert that buffer to a Swift string.
    ///
    /// Unlike `decodeFixedCString`, this is for dynamic buffers like `[CChar]`,
    /// not fixed-size struct fields imported as tuples.
    func decodeCStringBuffer(_ buffer: [CChar]) -> String? {
        guard let nullIndex = buffer.firstIndex(of: 0) else {
            return nil // no null terminator found
        }

        let slice = buffer[..<nullIndex]
        let bytes = slice.map { UInt8(bitPattern: $0) }

        return String(decoding: bytes, as: UTF8.self)
    }
