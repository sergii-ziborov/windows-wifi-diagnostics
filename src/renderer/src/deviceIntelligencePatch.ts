import type {
  DeviceIntelligenceOverride,
  MacEnrichment,
  VulnerabilityIntelAssessment,
  VulnerabilityIntelSignal,
  WindowsWifiNetwork
} from '../../collector/types';

export function applyDeviceIntelligenceOverrideToNetwork(
  network: WindowsWifiNetwork,
  override: DeviceIntelligenceOverride
): WindowsWifiNetwork {
  return {
    ...network,
    mac_enrichment: mergeMacEnrichment(network.mac_enrichment, override, network.bssid, network.ssid),
    vulnerability_intel: mergeVulnerabilityIntel(network.vulnerability_intel, override, network)
  };
}

export function patchNetworkListWithDeviceIntelligence(
  networks: WindowsWifiNetwork[],
  target: WindowsWifiNetwork,
  override: DeviceIntelligenceOverride
): WindowsWifiNetwork[] {
  return networks.map((network) =>
    sameNetworkIdentity(network, target) ? applyDeviceIntelligenceOverrideToNetwork(network, override) : network
  );
}

export function sameNetworkIdentity(left: WindowsWifiNetwork, right: WindowsWifiNetwork): boolean {
  const leftBssid = normalizeMacAddress(left.bssid);
  const rightBssid = normalizeMacAddress(right.bssid);
  if (leftBssid && rightBssid) {
    return leftBssid === rightBssid;
  }

  const leftSsid = normalizeSsid(left.ssid);
  const rightSsid = normalizeSsid(right.ssid);
  return Boolean(
    leftSsid &&
      rightSsid &&
      leftSsid === rightSsid &&
      left.channel === right.channel &&
      (left.radio_type ?? null) === (right.radio_type ?? null)
  );
}

function mergeMacEnrichment(
  existing: MacEnrichment | undefined,
  override: DeviceIntelligenceOverride,
  bssid: string | null,
  ssid: string | null
): MacEnrichment {
  const normalizedMac = existing?.normalized_mac ?? normalizeMacAddress(bssid);
  const oui = existing?.oui ?? override.oui ?? (normalizedMac ? normalizedMac.split(':').slice(0, 3).join(':') : null);

  return {
    normalized_mac: normalizedMac,
    oui,
    vendor: override.vendor ?? existing?.vendor ?? null,
    address_scope: existing?.address_scope ?? 'unknown',
    device_hint: override.device_hint ?? existing?.device_hint ?? inferHintFromOverride(override, ssid),
    confidence: maxConfidence(existing?.confidence ?? 'low', override.confidence),
    source: uniqueStrings([existing?.source ?? null, override.source]).join('+'),
    notes: uniqueStrings([
      ...(existing?.notes ?? []),
      ...override.notes.map((note) => `Saved AI intel: ${note}`),
      override.device_role ? `Saved device role: ${override.device_role}` : null,
      override.model ? `Saved model hint: ${override.model}` : null,
      override.is_mesh === true ? 'Saved role marks this AP as mesh-capable or a mesh node' : null
    ])
  };
}

function mergeVulnerabilityIntel(
  existing: VulnerabilityIntelAssessment | undefined,
  override: DeviceIntelligenceOverride,
  network: WindowsWifiNetwork
): VulnerabilityIntelAssessment | undefined {
  if (!override.vulnerability_summary && !override.exposure_level && override.vulnerability_references.length === 0) {
    return existing;
  }

  const signal: VulnerabilityIntelSignal = {
    id: 'identity.saved_device_intelligence',
    label: 'Saved device intelligence',
    severity: severityFromExposure(override.exposure_level ?? 'watch'),
    confidence: override.confidence,
    summary:
      override.vulnerability_summary ??
      `Saved role ${override.device_role ?? override.device_hint ?? 'device'} should be inventoried before CVE matching.`,
    evidence: uniqueStrings([
      `ssid=${network.ssid ?? 'hidden'}`,
      `bssid=${network.bssid ?? 'unknown'}`,
      override.vendor ? `vendor=${override.vendor}` : null,
      override.model ? `model=${override.model}` : null,
      override.device_role ? `role=${override.device_role}` : null
    ]),
    references: override.vulnerability_references.map((url) => ({ label: url, url }))
  };

  const signals = [...(existing?.signals ?? []), signal];
  const exposureLevel = maxExposure(existing?.exposure_level ?? 'none', override.exposure_level ?? exposureFromSignal(signal));

  return {
    source: 'local_vulnerability_seed.v1',
    exposure_level: exposureLevel,
    confidence: maxConfidence(existing?.confidence ?? 'low', override.confidence),
    summary: exposureSummary(exposureLevel, existing?.summary, signal.summary),
    signals,
    notes: uniqueStrings([
      ...(existing?.notes ?? []),
      'Saved device intelligence can improve passive exposure triage, but exact CVE matching still needs model and firmware.',
      ...override.notes.map((note) => `Saved AI intel: ${note}`)
    ])
  };
}

function inferHintFromOverride(override: DeviceIntelligenceOverride, ssid: string | null): string | null {
  if (override.device_role && override.device_role !== 'unknown') {
    return override.device_role.replace(/_/g, ' ');
  }

  const normalizedSsid = normalizeSsid(ssid);
  if (normalizedSsid.includes('mesh')) {
    return 'mesh node';
  }
  if (normalizedSsid.includes('print') || normalizedSsid.startsWith('direct-')) {
    return 'printer';
  }

  return null;
}

function normalizeMacAddress(value: string | null | undefined): string | null {
  const hex = value?.replace(/[^a-fA-F0-9]/g, '').toLowerCase() ?? '';
  if (hex.length !== 12) {
    return null;
  }

  return hex.match(/.{2}/g)?.join(':') ?? null;
}

function normalizeSsid(value: string | null | undefined): string {
  return value?.trim().toLowerCase() ?? '';
}

function maxConfidence(left: MacEnrichment['confidence'], right: MacEnrichment['confidence']): MacEnrichment['confidence'] {
  const order: Record<MacEnrichment['confidence'], number> = { low: 0, medium: 1, high: 2 };
  return order[right] > order[left] ? right : left;
}

function maxExposure(
  left: VulnerabilityIntelAssessment['exposure_level'],
  right: VulnerabilityIntelAssessment['exposure_level']
): VulnerabilityIntelAssessment['exposure_level'] {
  const order: Record<VulnerabilityIntelAssessment['exposure_level'], number> = {
    none: 0,
    watch: 1,
    review: 2,
    priority: 3
  };
  return order[right] > order[left] ? right : left;
}

function severityFromExposure(level: VulnerabilityIntelAssessment['exposure_level']): VulnerabilityIntelSignal['severity'] {
  if (level === 'priority') {
    return 'high';
  }
  if (level === 'review') {
    return 'medium';
  }
  return 'low';
}

function exposureFromSignal(signal: VulnerabilityIntelSignal): VulnerabilityIntelAssessment['exposure_level'] {
  if (signal.severity === 'high') {
    return 'priority';
  }
  if (signal.severity === 'medium') {
    return 'review';
  }
  return 'watch';
}

function exposureSummary(
  level: VulnerabilityIntelAssessment['exposure_level'],
  existingSummary: string | undefined,
  savedSummary: string
): string {
  if (level === 'priority') {
    return `Priority review: ${savedSummary}`;
  }
  if (level === 'review') {
    return `Inventory review: ${savedSummary}`;
  }
  if (level === 'watch') {
    return `Watch: ${savedSummary}`;
  }

  return existingSummary ?? 'No passive vulnerability exposure signals from current metadata.';
}

function uniqueStrings(values: Array<string | null | undefined>): string[] {
  const output: string[] = [];
  const seen = new Set<string>();

  for (const value of values) {
    const normalized = value?.trim();
    if (!normalized || seen.has(normalized)) {
      continue;
    }

    seen.add(normalized);
    output.push(normalized);
  }

  return output;
}
