import type { MacEnrichment, MacIntelligenceBucket, MacIntelligenceSummary, WindowsWifiNetwork } from './types';

interface OuiSeedRecord {
  vendor: string;
  deviceFamily: string;
}

const OUI_SEED_SOURCE = 'local_oui_seed.v1';

const OUI_SEED: Record<string, OuiSeedRecord> = {
  '00:f8:cc': {
    vendor: 'Sagemcom Broadband SAS',
    deviceFamily: 'consumer router / broadband gateway'
  },
  '08:5b:0e': {
    vendor: 'Fortinet, Inc.',
    deviceFamily: 'network security appliance / access point'
  },
  '40:ae:30': {
    vendor: 'TP-Link Systems Inc',
    deviceFamily: 'consumer router / range extender'
  },
  '48:4a:e9': {
    vendor: 'Hewlett Packard Enterprise',
    deviceFamily: 'enterprise access point / network equipment'
  },
  '7c:57:3c': {
    vendor: 'Hewlett Packard Enterprise',
    deviceFamily: 'enterprise access point / network equipment'
  },
  '80:8d:b7': {
    vendor: 'Hewlett Packard Enterprise',
    deviceFamily: 'Aruba / HPE enterprise access point'
  },
  'ac:d1:b8': {
    vendor: 'Hon Hai Precision Ind. Co.,Ltd.',
    deviceFamily: 'OEM Wi-Fi module'
  },
  'e0:46:ee': {
    vendor: 'NETGEAR',
    deviceFamily: 'consumer router / access point'
  }
};

export function enrichMacAddress(mac: string | null, ssid: string | null): MacEnrichment {
  const normalized = normalizeMacAddress(mac);
  const notes: string[] = [];

  if (!normalized) {
    return {
      normalized_mac: null,
      oui: null,
      vendor: null,
      address_scope: 'invalid',
      device_hint: inferDeviceHintFromSsid(ssid),
      confidence: 'low',
      source: OUI_SEED_SOURCE,
      notes: ['MAC address was missing or invalid']
    };
  }

  const scope = classifyMacAddress(normalized);
  const oui = normalized.split(':').slice(0, 3).join(':');
  const ouiRecord = scope === 'global' ? OUI_SEED[oui] : undefined;
  const ssidHint = inferDeviceHintFromSsid(ssid);

  if (scope === 'local') {
    notes.push('Locally administered MAC; OUI vendor lookup is unreliable');
  } else if (scope === 'multicast') {
    notes.push('Multicast/group MAC; not a normal AP hardware address');
  }

  if (!ouiRecord && scope === 'global') {
    notes.push('OUI prefix is not in the local seed database yet');
  }

  if (ssidHint) {
    notes.push('Device hint includes SSID pattern evidence');
  }

  const deviceHint = ssidHint ?? ouiRecord?.deviceFamily ?? null;
  const confidence = estimateConfidence(Boolean(ouiRecord), Boolean(ssidHint), scope);

  return {
    normalized_mac: normalized,
    oui,
    vendor: ouiRecord?.vendor ?? null,
    address_scope: scope,
    device_hint: deviceHint,
    confidence,
    source: OUI_SEED_SOURCE,
    notes
  };
}

export function ensureNetworkMacEnrichment(network: WindowsWifiNetwork): WindowsWifiNetwork {
  if (network.mac_enrichment) {
    return network;
  }

  return {
    ...network,
    mac_enrichment: enrichMacAddress(network.bssid, network.ssid)
  };
}

export function summarizeMacIntelligence(networks: WindowsWifiNetwork[]): MacIntelligenceSummary {
  const vendors = new Map<string, number>();
  const deviceHints = new Map<string, number>();
  const unknownOuis = new Map<string, number>();
  const confidenceCounts: MacIntelligenceSummary['confidence_counts'] = {
    low: 0,
    medium: 0,
    high: 0
  };
  let knownVendorCount = 0;
  let unknownVendorCount = 0;
  let globalMacCount = 0;
  let localMacCount = 0;
  let multicastMacCount = 0;
  let invalidMacCount = 0;

  for (const network of networks) {
    const enrichment = network.mac_enrichment;
    if (!enrichment) {
      unknownVendorCount += 1;
      invalidMacCount += 1;
      continue;
    }

    confidenceCounts[enrichment.confidence] += 1;

    if (enrichment.vendor) {
      knownVendorCount += 1;
      increment(vendors, enrichment.vendor);
    } else {
      unknownVendorCount += 1;
      if (enrichment.oui && enrichment.address_scope === 'global') {
        increment(unknownOuis, enrichment.oui);
      }
    }

    if (enrichment.device_hint) {
      increment(deviceHints, enrichment.device_hint);
    }

    switch (enrichment.address_scope) {
      case 'global':
        globalMacCount += 1;
        break;
      case 'local':
        localMacCount += 1;
        break;
      case 'multicast':
        multicastMacCount += 1;
        break;
      case 'invalid':
      case 'unknown':
        invalidMacCount += 1;
        break;
    }
  }

  return {
    source: OUI_SEED_SOURCE,
    known_vendor_count: knownVendorCount,
    unknown_vendor_count: unknownVendorCount,
    global_mac_count: globalMacCount,
    local_mac_count: localMacCount,
    multicast_mac_count: multicastMacCount,
    invalid_mac_count: invalidMacCount,
    confidence_counts: confidenceCounts,
    vendors: sortBuckets(vendors),
    device_hints: sortBuckets(deviceHints),
    unknown_ouis: sortBuckets(unknownOuis),
    notes: [
      'Vendor names are inferred from the local OUI seed only.',
      'Locally administered/randomized MAC addresses cannot be reliably mapped to a hardware vendor.',
      'Device hints combine OUI evidence with SSID naming patterns when available.'
    ]
  };
}

function normalizeMacAddress(mac: string | null): string | null {
  if (!mac) {
    return null;
  }

  const hex = mac.replace(/[^a-fA-F0-9]/g, '').toLowerCase();
  if (hex.length !== 12) {
    return null;
  }

  return hex.match(/.{2}/g)?.join(':') ?? null;
}

function classifyMacAddress(mac: string): MacEnrichment['address_scope'] {
  const firstOctet = Number.parseInt(mac.slice(0, 2), 16);
  if (!Number.isFinite(firstOctet)) {
    return 'invalid';
  }

  if ((firstOctet & 1) === 1) {
    return 'multicast';
  }

  if ((firstOctet & 2) === 2) {
    return 'local';
  }

  return 'global';
}

function inferDeviceHintFromSsid(ssid: string | null): string | null {
  const normalizedSsid = ssid?.trim().toLowerCase() ?? '';
  if (!normalizedSsid) {
    return null;
  }

  if (normalizedSsid.startsWith('direct-') && normalizedSsid.includes('hp')) {
    return 'HP printer Wi-Fi Direct';
  }

  if (normalizedSsid.startsWith('hp-print')) {
    return 'HP printer';
  }

  if (normalizedSsid.includes('xerox')) {
    return 'Xerox printer Wi-Fi Direct';
  }

  if (normalizedSsid.includes('polk magnifi')) {
    return 'Polk MagniFi soundbar / speaker';
  }

  if (
    normalizedSsid.includes('mesh') ||
    normalizedSsid.includes('router') ||
    normalizedSsid.includes('gateway')
  ) {
    return 'home router / mesh node';
  }

  return null;
}

function estimateConfidence(
  hasOuiVendor: boolean,
  hasSsidHint: boolean,
  scope: MacEnrichment['address_scope']
): MacEnrichment['confidence'] {
  if (hasOuiVendor && hasSsidHint) {
    return 'high';
  }

  if (hasSsidHint) {
    return scope === 'local' ? 'medium' : 'high';
  }

  if (hasOuiVendor) {
    return 'medium';
  }

  return 'low';
}

function increment(map: Map<string, number>, key: string): void {
  map.set(key, (map.get(key) ?? 0) + 1);
}

function sortBuckets(map: Map<string, number>): MacIntelligenceBucket[] {
  return [...map.entries()]
    .map(([value, count]) => ({ value, count }))
    .sort((left, right) => right.count - left.count || left.value.localeCompare(right.value));
}
