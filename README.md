# macOS Process Trust Inspector

**Helpful process identity inspection for macOS.**

macOS Process Trust Inspector is an explanation-first tool for understanding *what a running process is*, *where it came from*, and *which trust and enforcement signals apply*, without turning those signals into alarms or verdicts.

This tool is designed for engineers, security practitioners, and technically curious users who want clarity and context, not malware scores.

---

## What this tool is

macOS Process Trust Inspector provides a **human-readable narrative** explaining the identity and trust characteristics of running processes.

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

Nothing is inferred silently, and missing data is treated as *unavailable*, not suspicious.

---

## What this tool is not

This tool intentionally does **not**:

- Perform malware detection
- Assign risk scores
- Produce safety verdicts
- Observe runtime memory behavior
- Perform Gatekeeper or notarization assessments

A valid code signature does **not** imply safety.  
An unsigned process does **not** imply maliciousness.

The goal isvisibility and understanding, not judgment.

---

## Design philosophy

### Explanation-first

macOS security signals are subtle, layered, and frequently misunderstood.

This tool treats each signal as *evidence*, not a conclusion, and explains:
- what the signal means
- where it applies
- what it does **not** prove

### Best-effort, explicit uncertainty

macOS inspection APIs are inherently partial and time-sensitive; processes can exit or change while they are being inspected. 
Processes exit. Metadata is missing. Privileges vary.

This tool makes uncertainty explicit instead of hiding it:
- Unknown values are labeled and explained
- Limits are surfaced alongside results
- Absence of data is never silently reinterpreted

### Static identity, not runtime behavior

All signing and trust signals are derived from **on-disk executables**, not live memory state.

---

## Copy & selection behavior

This tool intentionally distinguishes between **narrative text** and **structured evidence** in its UI.

Narrative content (summaries, interpretations, and limits) is rendered as continuous text blocks so it can be freely selected and copied like a document or report.

Structured evidence rows (such as runtime constraints and provenance signals) are presented as discrete, semantic rows with icons that match macOS system conventions and accessibility expectations. Due to SwiftUI limitations, rows that mix icons and text do not support seamless drag-selection across elements.

Where copying structured values is useful, explicit copy actions are provided instead of relying on drag selection.

This is a deliberate tradeoff:
- **Narrative text** is optimized for reading and copying
- **Evidence rows** are optimized for clarity, structure, and correctness

---

## Note on WebKit helper processes and "Apple Software"

Some processes shown in the list (for example entries labeled  
**"ChatGPT ... Web Content"** or **"zoom.us ... Web Content"**) are **WebKit helper processes provided by Apple**, not third-party executables.

These processes use Apple system binaries such as:

- `com.apple.WebKit.WebContent`
- Located under `/System/Library/Frameworks`

Even though their *display name* reflects the application that launched them, the **executable itself is supplied and signed by Apple**.

In these cases, Process Trust Inspector observes:
- A valid Apple code signature
- Apple-controlled identifiers
- System framework locations
- Apple signing metadata

Based on this evidence, the process is correctly classified as **Apple Software**, even though the visible name reflects a third-party host application.

The name indicates **which application launched the helper**, not **who supplied the executable**.

This distinction is intentional in v1. Future versions may make this relationship more explicit in the UI to reduce confusion.

---

## Scope and limitations (v1)

Version 1 intentionally focuses on a **stable, interpretable core**.

Included in v1:
- Static code-signing identity
- App Store certificate policy evidence
- App Sandbox and Hardened Runtime (declared)
- Bundled vs bare executable context
- Quarantine metadata and Gatekeeper relevance (best-effort)

Explicitly excluded from v1:
- TCC permission state
- Full entitlement enumeration
- SIP / AMFI internals
- Runtime injection or dylib analysis
- XPC service relationships

These exclusions are deliberate. Many of these signals are noisy, privilege-sensitive, or easy to misinterpret without deeper context.

---

## Implementation note

This project also reflects a personal return to macOS programming after a long hiatus.

I used it as an opportunity to acquaint myself with:
- Swift
- macOS internals
- Swift <-> C / Core Foundation boundaries
- macOS security and trust mechanisms

Adding deep SwiftUI expertise on top of that was outside my primary interest and, frankly, too much at once.

As a result:
- **The UI design is mine**
- **Most SwiftUI implementation code was produced with assistance from OpenAI and Gemini**
- **All security modeling, trust classification, signal interpretation, and explanatory logic reflect my own analysis and design**

I'm comfortable with that tradeoff.

---

## Who this is for

- macOS engineers
- Security engineers and defenders
- Incident responders
- Platform and endpoint teams
- Curious power users who want explanations, not alerts

If you've ever asked *"what exactly does macOS know about this process?"*, this tool is for you.

---

## License

MIT License.

You are free to use, modify, and distribute this software under the terms of the MIT license. See the `LICENSE` file for details.