# macOS Process Trust Inspector
![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)

**Helpful process identity inspection for macOS.**

macOS Process Trust Inspector is an explanation-oriented tool for understanding what a running process is, where it came from, and which trust and enforcement signals may apply, without turning those signals into conclusions.

This tool is designed for engineers, security practitioners, and technically curious users who want clarity and context rather than malware scores.

---

## What this tool is

macOS Process Trust Inspector provides a human-readable narrative explaining the identity and trust characteristics of running processes.

For a selected process, it explains:

- **Identity**
  - Process name, PID, user ID, parent process
  - Bundle identifier and executable path
- **Code signing**
  - Publisher identity (Apple / App Store / Developer ID / Unsigned)
  - Signature validity
  - Presence of entitlements
- **Provenance**
  - Quarantine metadata
  - When Gatekeeper checks are likely to apply
- **Runtime constraints**
  - App Sandbox
  - Hardened Runtime

Each section explicitly separates:
- **Observed facts**
- **Interpretation**
- **Limits & uncertainty**

Nothing is inferred silently, and missing data is treated as unavailable rather than suspicious.

---

## What this tool is not

This tool intentionally does **not**:

- Perform malware detection
- Assign risk scores
- Produce safety verdicts
- Observe runtime memory behavior
- Perform Gatekeeper or notarization assessments

A valid code signature does **not** imply safety.  
An unsigned process does **not** imply malicious intent.

The goal is visibility and understanding, not judgment.

---

## Who this is for

- macOS engineers
- Security engineers and defenders
- Incident responders
- Platform and endpoint teams
- Curious power users who want explanations, not alerts

If you have ever asked "what exactly does macOS know about this process?", this tool may interest you.

---

## Design philosophy

macOS security signals are layered and can be difficult to understand.

This tool treats each signal as *evidence*, not a conclusion, and explains:
- what the signal means
- where it applies
- what it does **not** prove

### Best-effort, explicit uncertainty

macOS inspection APIs are inherently partial and time-sensitive; processes can exit or change while they are being inspected. Metadata may be missing and privileges vary.

This tool tries to make uncertainty explicit.

- Unknown values are labeled and explained
- Limits are surfaced alongside results
- Absence of data is never silently reinterpreted

### Static identity, not runtime behavior

All signing and trust signals are derived from **on-disk executables**, not live memory state.

---

## Note on WebKit helper processes and "Apple Software"

Some processes shown in the list are Apple-provided WebKit helper processes, not third-party executables. Examples include display names such as "ChatGPT ... Web Content" and "zoom.us ... Web Content."

These processes use Apple system binaries such as:

- `com.apple.WebKit.WebContent`
- Located under `/System/Library/Frameworks`

Even though the display name reflects the application that launched the helper, the executable itself is supplied and signed by Apple.

In these cases, Process Trust Inspector observes:
- A valid Apple code signature
- Apple-controlled identifiers
- System framework locations
- Apple signing metadata

Based on this evidence, the process is classified as **Apple Software**, even though the visible name reflects a third-party host application.

The name indicates which application launched the helper, not who supplied the executable.

This distinction is intentional in v1. Future versions may make this relationship more explicit in the UI.

---

## Scope and limitations (v1)

Version 1 intentionally focuses on a **stable, interpretable core**.

Included in v1:
- Static code-signing identity
- App Store certificate policy evidence
- App Sandbox and Hardened Runtime (declared)
- Bundled vs bare executable context
- Quarantine metadata and inferred Gatekeeper relevance

Explicitly excluded from v1:
- TCC permission state
- Full entitlement enumeration
- SIP / AMFI internals
- Runtime injection or dylib analysis
- XPC service relationships

These exclusions are deliberate for v1 but may be revisited in the future. Many of these signals are noisy, privilege-sensitive, or easy to misinterpret without additional context.

### Process enumeration scope

Process listing in v1 is derived from NSWorkspace (LaunchServices). This includes user applications, background agents, and many helper processes, but it does not provide a complete view of all running processes on the system.

Command-line tools, daemons without LaunchServices registration, and certain low-level system processes may not appear in the list.

---

## Implementation note

This project reflects a return to macOS development for the first time since the mid-1990s, well before macOS X and Swift.

I used it as an opportunity to learn:
- Swift
- Modern macOS internals
- Swift <-> C / Core Foundation boundaries
- macOS code signing and trust mechanisms

Adding SwiftUI expertise on top of that was outside my primary interest and too much to take on at once.

All inspection logic, trust classification, signal evaluation, narrative construction, and system interaction code were designed and implemented by me.

Most SwiftUI implementation code was produced with assistance from OpenAI and Gemini. The UI layout reflects my design decisions; I chose to use AI tools for SwiftUI implementation rather than invest cognitive energy into framework mechanics.

---

## License

MIT License

Copyright (c) 2026 Aaron Weiss

You are free to use, modify, and distribute this software under the terms of the MIT license. See the `LICENSE` file for details.