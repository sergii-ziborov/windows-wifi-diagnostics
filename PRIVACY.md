# Privacy model

Windows Wi-Fi Diagnostics is local-first and has no background analytics or telemetry.

## Data read locally

Depending on the action selected, the app can read:

- Wi-Fi interface state, SSID, BSSID, signal, channel, and security metadata;
- local IP configuration, gateway, DNS, and neighbor-cache entries;
- Windows WLAN AutoConfig events;
- saved Wi-Fi profile details, including a password only after an explicit reveal action;
- host and adapter identity when the experimental scan-identity panel is used.

During source development, captures and SQLite state are stored under `data/`. That directory is excluded from Git and must be treated as sensitive.

## Network activity

- Baseline collection and passive LAN inventory use local Windows state.
- The internet reachability check contacts Cloudflare only after the operator requests it.
- Poll and active LAN profiles send traffic to the local network and are visibly labelled before use.
- Optional Codex or Claude review passes selected evidence to the configured external CLI provider. The provider's own privacy policy then applies.

## Credentials

Saved Wi-Fi passwords are requested from Windows only on demand, displayed in renderer memory, and are not intentionally persisted by the application. Do not include revealed credentials in screenshots, exports, logs, or issue reports.

## Sharing diagnostics

Before sharing a report or diagnostics bundle, redact SSIDs, BSSIDs, MAC addresses, IP addresses, hostnames, usernames, absolute paths, and any saved credential material.
