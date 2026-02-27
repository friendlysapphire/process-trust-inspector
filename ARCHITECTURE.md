# Architecture

This app uses a simple, explicit narrative contract so UI behavior stays predictable as the project grows.

## Core Rules

- Section routing is key-based.
- Fact grouping and specialized behavior are key-based.
- UI and export copy are resolved from `NarrativeDisplayCopy`.
- Specialized renderers must include a generic fallback path for unhandled facts.
- Debug invariants should catch dropped or double-rendered facts early.

## Data Flow

1. Inspectors gather raw process/signing/provenance/runtime data.
2. `InspectorEngine` builds a `ProcessSnapshot`.
3. `NarrativeBuilder` transforms snapshot data into `EngineNarrative`.
4. UI renders `EngineNarrative` in `ProcessDetailView`.
5. Export uses the same `EngineNarrative` model (`EngineNarrative+Export`).

## Identity vs Copy

- Semantic identity:
  - `NarrativeSection.key` (`NarrativeSectionKey`)
  - `FactLine.key` (`FactLineKey`)
- Display copy:
  - Section titles, fact labels, and selected helper text come from `NarrativeDisplayCopy`.
- Fallback behavior:
  - If no mapping exists, use the model’s existing `title`/`label`.

## Specialized Rendering Contract

Specialized blocks (for example, Provenance) may render known facts with custom UI, but must also render remaining facts generically.

Expected behavior:
- No facts are silently dropped.
- No facts are rendered twice.

## Debug Safety

Use debug assertions in specialized renderers to enforce:
- `allFacts == specializedFacts + fallbackFacts`
- `specializedFacts ∩ fallbackFacts == empty`

## Why This Structure

- Reduces brittle string matching.
- Keeps copy ownership in one place.
- Keeps UI/export aligned.
- Makes changes easier to reason about in a solo project.
