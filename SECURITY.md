# Security policy

## Supported version

Only the latest commit on `main` is supported while the project is in portfolio beta.

## Reporting a vulnerability

Please use GitHub's private security-advisory workflow for this repository. Do not place credentials, real network captures, SSIDs, MAC addresses, IP addresses, or diagnostics bundles in a public issue.

Include a concise reproduction, expected impact, affected files or versions, and a sanitized proof of concept.

## Operating safety

- Use active LAN checks only on networks you own or are authorized to test.
- Treat scan-identity changes as experimental; they can interrupt Wi-Fi, NAC, VPN, or domain access.
- Reveal saved Wi-Fi credentials only on your own Windows profile and never capture them in screenshots.
- Do not distribute unsigned installer artifacts as production downloads;
  Windows builds require code signing and macOS builds require Developer ID
  signing plus notarization.
- Exposure hints are not proof of a vulnerability and should be verified against an exact device model and firmware version.
