# Learning Map

This is a practical guide to understanding how Process Trust Inspector turns raw process data into UI and export output.

## 1) Start Here (High-Level Flow)

1. `InspectorEngine` collects process/snapshot data.
2. `NarrativeBuilder` converts snapshot data into `EngineNarrative`.
3. `ProcessDetailView` renders `EngineNarrative` in the app UI.
4. `EngineNarrative+Export` renders the same model for plain text / Markdown export.

Core files:
- `ProcessTrustInspector/ProcessTrustInspector/Engine/InspectorEngine.swift`
- `ProcessTrustInspector/ProcessTrustInspector/Engine/NarrativeBuilder.swift`
- `ProcessTrustInspector/ProcessTrustInspector/Models/EngineNarrative.swift`
- `ProcessTrustInspector/ProcessTrustInspector/Views/ProcessDetailView.swift`
- `ProcessTrustInspector/ProcessTrustInspector/Models/EngineNarrative+Export.swift`

## 2) Model Contract (Most Important Mental Model)

`EngineNarrative.swift` defines the render contract.

- `NarrativeSection.key` (`NarrativeSectionKey`) is semantic section identity.
- `FactLine.key` (`FactLineKey`) is semantic fact identity.
- `title` / `label` are display strings and can change.
- `NarrativeDisplayCopy` is shared copy lookup for UI + export.

If you remember one thing: route/group by keys, not display strings.

## 3) Where Section/Fact Keys Are Assigned

`NarrativeBuilder.build(from:_:)` sets:
- section keys (`.identity`, `.processLineage`, `.codeSigning`, `.provenance`, `.runtimeConstraints`)
- fact keys for trust evidence, identity, lineage, signing, provenance, runtime

When adding a new fact:
1. Add a `FactLineKey` case.
2. Assign it in `NarrativeBuilder`.
3. Add copy mapping in `NarrativeDisplayCopy` if needed.
4. Decide whether specialized UI handles it or generic fallback is enough.

## 4) UI Rendering Map

`ProcessDetailView`:
- `SectionCard` routes specialized sections by `section.key`.
- `RuntimeConstraintsBlock` handles runtime section-specific row UI.
- `ProvenanceBlock` handles provenance-specific grouping.
- `FactRow` is generic fallback renderer for everything else.
- `LimitList` renders uncertainty/limits consistently.

Provenance safety:
- `ProvenanceBlock` computes specialized facts + `remainingFacts`.
- It always renders remaining facts generically.
- Debug assertions check no fact is dropped or double-rendered.

## 5) Export Rendering Map

`EngineNarrative+Export`:
- Uses the same `EngineNarrative` model as UI.
- Resolves section titles and fact labels through `NarrativeDisplayCopy`.
- Falls back to `section.title` / `fact.label` when no mapping exists.

This keeps export aligned with UI copy rules.

## 6) Fast Debug Traces

### Trace a missing UI row
1. Confirm fact exists in `NarrativeBuilder` output.
2. Check key assignment in `FactLine`.
3. Check specialized renderer (`RuntimeConstraintsBlock` / `ProvenanceBlock`).
4. Verify it is not filtered out before fallback render.

### Trace a label mismatch (UI vs export)
1. Check `NarrativeDisplayCopy.factLabel(...)`.
2. Check `FactRow.displayLabel` (UI path).
3. Check `FactLine.exportLabel` in export extension.

### Trace section misrouting
1. Check `NarrativeSection.key` in builder.
2. Check `SectionCard` routing by key.

## 7) Safe Editing Rules

- Prefer adding keys before adding logic.
- Keep specialized renderers narrow and explicit.
- Always preserve generic fallback for unknown/new facts.
- Keep copy changes in `NarrativeDisplayCopy`.
- Build after each slice (`xcodebuild ... Debug build`).

## 8) Suggested Reading Order (First Pass)

1. `EngineNarrative.swift` (keys + contract)
2. `NarrativeBuilder.swift` (where data becomes narrative facts)
3. `ProcessDetailView.swift` (how narrative is rendered)
4. `EngineNarrative+Export.swift` (same data, different output)
5. `ARCHITECTURE.md` (rules and guardrails)
