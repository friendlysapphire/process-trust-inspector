# macOS Process Trust Inspector
![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)

**Helpful process identity inspection for macOS.**

macOS Process Trust Inspector is an explanation-oriented tool for understanding what a running process is, where it came from, and which trust and enforcement signals may apply, without turning those signals into conclusions.

This tool is designed for engineers, security practitioners, and technically curious users who want clarity and context rather than risk scores.

---

## What this tool is

macOS Process Trust Inspector provides a structured, human-readable narrative explaining the identity and trust characteristics of running processes.

For a selected process, it explains:

- **Identity**
  - Process name, PID, user ID
  - Parent → child trust comparison (lineage context)
  - Bundle identifier and executable path
  - Executable location classification (system-owned, Applications, user-writable, etc.)
- **Code signing**
  - Publisher identity (Apple / App Store / Developer ID / Unsigned)
  - Signature validity
  - Presence of entitlements
  - Structural consistency notes (e.g. identifier mismatches, unexpected signing location)
  - **Provenance**
  - Quarantine metadata (present / absent / unavailable)
  - Parsed quarantine details (agent, first observed timestamp, event identifier when available)
  - Gatekeeper applicability (contextual, not an assessment)
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

A valid code signature does not imply safety.  
An unsigned process does not imply malicious intent.

The goal is visibility and understanding, not judgment.

---

## Recent additions (v1.3.5)

- Full process universe enumeration via **libproc (BSD layer)**, merged with NSWorkspace
- Explicit visibility modeling:
  - Visible via LaunchServices (NSWorkspace)
  - Visible via libproc only
- UI toggle between:
  - Applications only (LaunchServices-visible)
  - All processes (including background and non-GUI processes)
- Improved parent process resolution based on the full PID universe
- Clear labeling of partial or limited visibility
- Structured quarantine enrichment:
  - Parsed quarantine agent (e.g. browser or download source)
  - First observed timestamp (decoded from quarantine metadata)
  - Quarantine event identifier
  - Clear separation between quarantine presence and quarantine details
- Refined Gatekeeper applicability modeling (contextual, not an assessment)

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

This tool treats each signal as evidence, not a conclusion, and explains:
- what the signal means
- where it applies
- what it does not prove

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

This distinction is intentional. Future versions may make this relationship more explicit in the UI.

---

## Scope and limitations (v1.3)

Version 1.x intentionally focuses on a stable, interpretable core.

Included in v1.x:
- Visibility classification (LaunchServices vs libproc)
- Static code-signing identity
- App Store certificate policy evidence
- App Sandbox and Hardened Runtime (declared)
- Bundled vs bare executable context
- Quarantine metadata with structured enrichment (agent, timestamp, identifier)
- Inferred Gatekeeper applicability (contextual only)
- Parent process relationship context

Explicitly excluded from v1.x:
- TCC permission state
- Full entitlement enumeration
- SIP / AMFI internals
- Runtime injection or dylib analysis
- XPC service relationships

These exclusions are deliberate but may be revisited in the future. Many of these signals are noisy, privilege-sensitive, or easy to misinterpret without additional context.

### Process enumeration scope

Process listing in v1.3 is derived from two system layers:

- **libproc (BSD layer)** – the broad PID universe visible to the current user
- **NSWorkspace (LaunchServices layer)** – application-level processes

The engine merges both sources into a unified model.

By default, the UI shows processes visible via LaunchServices (applications and many background agents). You may expand the scope to include all processes visible via libproc, including:

- Background daemons
- Command-line tools
- Non-GUI processes
- Low-level system processes (subject to privilege constraints)

Visibility depends on user privileges and OS restrictions. Some processes may be partially observable.

---

## License

MIT License

Copyright (c) 2026 Aaron Weiss

You are free to use, modify, and distribute this software under the terms of the MIT license. See the `LICENSE` file for details.