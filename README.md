# RadioChron Desktop

Local-first Windows and macOS desktop diagnostics for recording Wi-Fi state,
comparing observations, and turning transient network problems into evidence
for a support ticket.

This is a separate Electron repository. It imports the public Node API from
[`radiochron-js`](https://github.com/sergii-ziborov/radiochron-js), which links
the [`radiochron`](https://github.com/sergii-ziborov/radiochron) Rust IoT core
through its packaged native Node adapter.

> Open-source beta. Download the unsigned test installers from
> [`desktop-v0.1.0-beta.1`](https://github.com/sergii-ziborov/radiochron-electron/releases/tag/desktop-v0.1.0-beta.1).
> Windows SmartScreen and macOS Gatekeeper may warn because this beta is not
> code-signed or notarized yet.

## Screenshots

Every value below is synthetic. SSIDs are invented, MAC addresses are locally
administered, and IP addresses come from documentation-only ranges.

![RadioChron Desktop overview with synthetic Wi-Fi data](docs/screenshots/radiochron-desktop-overview.png)

![RadioChron Desktop RF map with synthetic access points](docs/screenshots/radiochron-desktop-map.png)

![RadioChron Desktop network controls with synthetic addresses](docs/screenshots/radiochron-desktop-network.png)

![RadioChron Desktop channel pressure view with synthetic access points](docs/screenshots/radiochron-desktop-channels.png)

## What is implemented

- Native interface/association status and nearby BSS inventory through
  `radiochron-js` and the RadioChron Rust core.
- Typed Rust-core analysis, radio/authentication/DHCP/DNS/TCP/Internet path
  diagnosis, and an automatically started change-only local chronicle through
  `radiochron-js` (never through MCP).
- Windows Native WLAN and macOS CoreWLAN collectors with raw 802.11
  Information Element summaries, RSSI, channel, band, and security evidence.
- Saved baseline runs, comparisons, reconnect/environment observations,
  evidence timelines, and diagnostic bundles.
- AP/device inventory, a relative RF map, channel-pressure view, passive
  vulnerability context, and PDF evidence reports.
- Windows-only WLAN AutoConfig history, saved-profile inspection,
  local-neighbor workflow, and temporary scan-identity controls.
- A safe screenshot mode that never reads the host radio or network identity.

The RF map defaults to the `0.25` `wide+` spread correction so nearby synthetic
or real AP nodes remain readable instead of collapsing around the center.

## Platform support

| Capability | Windows x64 | Intel Mac | Apple Silicon Mac |
|---|---:|---:|---:|
| Current association | yes | yes | yes |
| Nearby BSS + beacon metadata | yes | yes | yes |
| Saved RadioChron baselines | yes | yes | yes |
| WLAN AutoConfig event history | yes | no OS equivalent | no OS equivalent |
| Saved Wi-Fi key / scan identity controls | yes | no | no |
| Installer artifact | NSIS `.exe` | DMG + ZIP | DMG + ZIP |

Recent macOS versions require Location Services before CoreWLAN exposes SSID,
BSSID, and scan identity. The bundle includes the usage description; permission
must still be granted interactively. Public macOS downloads must be signed with
Developer ID and notarized.

## Architecture

```text
radiochron-electron (Electron + React)
        |
        | import "radiochron"
        v
radiochron-js (Node/npm library)
        |
        | packaged radiochron-node-bridge
        v
radiochron (Rust IoT core)
        |-- Windows Native WLAN
        |-- Linux nl80211
        `-- macOS CoreWLAN
```

The native adapter keeps the JavaScript runtime and Rust collector
process-isolated. Electron uses the typed status, scan, BSS inventory, analysis,
connectivity, sampling, and chronicle APIs. Other Node applications can use the
same `radiochron-js` package without Electron. MCP is not part of this process.

## Development

Requirements: Node.js 22.12+ and Rust 1.80+.

```sh
npm ci
npm run native:build
npm run dev
```

Quality checks:

```sh
npm run check
npm run build
```

Regenerate the same privacy-safe screenshots used by this README and the site:

```sh
npm run screenshots
```

`RADIOCHRON_DEMO=1` activates synthetic IPC fixtures. The fixture uses
`192.0.2.0/24`, `2001:db8::/32`, and locally administered MAC addresses. It
does not query CoreWLAN, Windows WLAN APIs, profile secrets, neighbor tables,
or the real computer identity.

## Installers

Build on the target operating system:

```sh
# Windows x64 - assisted NSIS installer
npm run dist:win -- --x64

# macOS - choose the host architecture
npm run dist:mac -- --arm64
npm run dist:mac -- --x64
```

Outputs are written to `release/`. The native Node adapter and its provenance
file are embedded in the packaged resources. GitHub Actions builds Windows x64,
Intel Mac, and Apple Silicon installer artifacts. The current unsigned beta is
available for [Windows x64](https://github.com/sergii-ziborov/radiochron-electron/releases/download/desktop-v0.1.0-beta.1/RadioChron-Desktop-0.1.0-Windows-x64.exe),
[Apple Silicon](https://github.com/sergii-ziborov/radiochron-electron/releases/download/desktop-v0.1.0-beta.1/RadioChron-Desktop-0.1.0-macOS-Apple-Silicon.dmg),
and [Intel Mac](https://github.com/sergii-ziborov/radiochron-electron/releases/download/desktop-v0.1.0-beta.1/RadioChron-Desktop-0.1.0-macOS-Intel.dmg).

These beta installers are for testing. Windows code signing and macOS Developer
ID signing/notarization are still required for a production release.

A matching `v<package-version>` tag starts the production release workflow. It
fails closed without `WIN_CSC_LINK`/`WIN_CSC_KEY_PASSWORD` or the macOS
Developer ID and App Store Connect API-key secrets, verifies both architectures,
writes SHA-256 manifests, and creates a draft GitHub release for final review.

## Privacy and safety

- No telemetry, cookies, or analytics.
- Runtime state stays in the Electron user-data directory unless exported.
- SSIDs, BSSIDs, MAC addresses, IP configuration, and diagnostic bundles are
  sensitive network/location evidence; inspect them before sharing.
- Saved Wi-Fi secrets are Windows-only, revealed only after an explicit action,
  and never written to RadioChron inventory or demo fixtures.
- The renderer has no Node access; preload exposes a bounded, validated IPC API.

See [PRIVACY.md](PRIVACY.md) and [SECURITY.md](SECURITY.md).

## Repository family

- [`radiochron`](https://github.com/sergii-ziborov/radiochron) — dependency-light
  Rust IoT core.
- [`radiochron-js`](https://github.com/sergii-ziborov/radiochron-js) — Node/npm
  library over the core.
- [`radiochron-electron`](https://github.com/sergii-ziborov/radiochron-electron)
  — this separate desktop application.
- [`radiochron-site`](https://github.com/sergii-ziborov/radiochron-site) — website
  source.

Licensed under the [MIT License](LICENSE-MIT). The underlying `radiochron`
Rust core remains separately dual-licensed under MIT or Apache-2.0.
