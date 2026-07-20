# RadioChron Desktop

Local-first Windows desktop diagnostics for recording Wi-Fi state, comparing runs, and turning transient network problems into evidence that can be attached to a support ticket.

This is the desktop UI. The radio engine lives in
**[RadioChron](https://github.com/sergii-ziborov/radiochron)** — a pure-Rust
MCP server this app drives over stdio, exactly as an AI assistant would. One
engine, one source of truth, no duplicated collector logic.

> Open-source portfolio beta. This is not a packet sniffer, Wi-Fi geolocation system, or vulnerability scanner.

## Why it exists

Intermittent Wi-Fi failures are difficult to explain after the connection recovers. RadioChron Desktop collects the signals Windows already exposes, keeps a local history, highlights reconnect patterns and environmental changes, and produces a readable diagnostic record.

The useful workflow is:

```text
capture a baseline -> inspect history -> compare runs -> export evidence
```

## Current capabilities

- Current Windows Wi-Fi interface, IP configuration, BSSID, channel, signal, and security metadata.
- Nearby SSID/BSSID inventory through Windows Native WLAN and `netsh` fallbacks.
- WLAN AutoConfig event timeline with reconnect-loop symptom detection.
- Saved baseline runs, run analysis, run-to-run comparison, JSONL evidence, and diagnostics bundles.
- Relative RF view and channel-pressure view. Layout is signal-based and deterministic; it does not represent physical distance or location.
- Local AP/device history, OUI enrichment, security posture hints, and PDF evidence reports.
- Passive LAN neighbor inventory, with clearly labelled opt-in poll and active profiles.
- Optional external review through an installed Codex or Claude CLI.

Advanced controls can read a saved Windows Wi-Fi profile secret on explicit request or temporarily change scan identity. They are experimental, potentially disruptive, and are not part of the recommended baseline workflow.

## Requirements

- Windows 11 (the collectors depend on Windows WLAN, Event Log, PowerShell, and networking APIs).
- Node.js 22.12 or newer; Node.js 24 is recommended.
- npm.
- The [RadioChron](https://github.com/sergii-ziborov/radiochron) server binary
  for nearby-AP scanning. Build it with `cargo build --release` and either put it
  on `PATH` or point `RADIOCHRON_MCP` at it; a sibling `../radiochron`
  checkout is found automatically.

Scanning no longer compiles C# at runtime. The previous implementation reached
`wlanapi.dll` by emitting a C# shim through PowerShell `Add-Type`, which needed
the .NET CSC compiler on every call and tripped application-control policies on
managed machines. That path is gone.

## Run from source

```powershell
npm ci
npm run check
npm run dev
```

Create the production Electron bundles with:

```powershell
npm run build
```

The current build command produces unpackaged output under `out/`; a signed installer is not published yet.

## CLI examples

```powershell
npm run baseline:status
npm run baseline:networks
npm run baseline:collect -- --duration 60 --interval 5
npm run baseline:runs
npm run baseline:analyze
npm run baseline:report
```

## Architecture

```text
Windows WLAN / Event Log / IP / neighbor sources
                    |
      RadioChron (Rust MCP server)  +  platform adapters
                    |
     collectors, history, analysis, SQLite
                    |
          Electron main process IPC
                    |
         sandboxed preload bridge
                    |
             React renderer
```

Nearby-AP scanning and the native BSS list (real dBm, channel frequencies,
802.11 capability flags) come from the RadioChron MCP server. The app locates
the binary via `RADIOCHRON_MCP`, then a packaged copy, then a sibling
`../radiochron` development checkout, then `PATH`.

Source layout:

- `src/mcp/` — MCP stdio client for the RadioChron server.
- `src/platform/windows/` — Windows commands and the RadioChron bridge.
- `src/collector/` — collection, persistence, inventory, comparison, and evidence logic.
- `src/analysis/` — timeline and reconnect symptom analysis.
- `src/main/` and `src/preload/` — Electron security boundary and IPC bridge.
- `src/renderer/` — React desktop interface.
- `tests/` — synthetic fixtures and unit/integration coverage for parsers and analysis.

## Privacy and safety

Captured SSIDs, BSSIDs, MAC addresses, IP addresses, event logs, and saved network profiles are sensitive. Runtime state is kept locally under `data/` during development and is excluded from Git. Do not attach an unredacted diagnostics bundle to a public issue.

The application has no background telemetry. Internet reachability is checked only when requested. External AI review is optional and sends the displayed evidence to the CLI provider selected by the operator. See [PRIVACY.md](PRIVACY.md) and [SECURITY.md](SECURITY.md).

Only run active LAN checks or identity changes on systems and networks you own or are authorized to test.

## Honest limitations

- No raw 802.11 management-frame capture, packet injection, or deauthentication proof.
- Nearby AP visibility depends on the adapter, driver, Windows locale, and permissions.
- The relative RF view is a visualization, not ranging or geolocation.
- Exposure labels are evidence-based review hints, not CVE confirmation.
- The UI is functional but still contains a large renderer module that should be split before long-term product development.
- Windows localization and packaged-data paths need broader validation before a general release.

## Product direction

The project is intentionally focused on a Windows Wi-Fi incident recorder and evidence notebook: baseline, history, comparison, and truthful reporting. Generic heat-mapping, offensive Wi-Fi tooling, and custom AX211 driver research are out of scope for this repository.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.
