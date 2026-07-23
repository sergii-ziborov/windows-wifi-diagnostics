# Privacy model

RadioChron Desktop is local-first and has no background analytics or telemetry.

## Data read locally

Depending on the action selected, the app can read:

- Wi-Fi interface state, SSID, BSSID, signal, channel, and security metadata;
- local IP configuration, gateway, DNS, and neighbor-cache entries;
- Windows WLAN AutoConfig events when running on Windows;
- nearby Bluetooth Low Energy advertisements after an explicit scan;
- Windows-known Bluetooth device names, paired/connected state, transport, and
  device type after an explicit scan;
- saved Wi-Fi profile details, including a password only after an explicit reveal action;
- host and adapter identity when the experimental scan-identity panel is used.

Installed builds keep state in Electron's per-user application-data directory.
Bluetooth analytics store privacy-minimized opaque identity keys, system IDs,
names, paired/connected state, transport/type, RSSI
evidence, address type, assigned Company IDs, advertised service UUIDs,
connectable/Tx-power flags, zones, and scan timestamps for at most 30 days or
512 scans. The analytics archive does not store raw Bluetooth addresses, raw
Windows device IDs, or raw
manufacturer/service payload bytes. `Reset history` removes the archive and
resets the in-process detector.
Source development may also use `data/`; that directory is excluded from Git
and must be treated as sensitive.

## Network activity

- Baseline collection uses native RadioChron collectors. Windows uses the WLAN
  API; macOS uses CoreWLAN and requires Location Services for SSID/BSSID access.
- Bluetooth scans use WinRT on Windows and CoreBluetooth on macOS, only when
  requested by the operator. Windows also reads the local DeviceInformation
  inventory; no Bluetooth inventory is sent to a server.
- The documentation screenshot mode uses synthetic fixtures and does not query
  the host radio, addresses, neighbor cache, profile secrets or computer name.
- The internet reachability check contacts Cloudflare only after the operator requests it.
- Poll and active LAN profiles send traffic to the local network and are visibly labelled before use.
- Optional Codex or Claude review passes selected evidence to the configured external CLI provider. The provider's own privacy policy then applies.

## Credentials

Saved Wi-Fi passwords are requested from Windows only on demand, displayed in renderer memory, and are not intentionally persisted by the application. Do not include revealed credentials in screenshots, exports, logs, or issue reports.

## Sharing diagnostics

Before sharing a report or diagnostics bundle, redact SSIDs, BSSIDs, MAC addresses, IP addresses, hostnames, usernames, absolute paths, and any saved credential material.
