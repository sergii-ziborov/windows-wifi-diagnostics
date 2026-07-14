import type { WindowsNativeBssEntry, WindowsWifiNetwork } from './types';

export function mergeNativeBssDetails(
  networks: WindowsWifiNetwork[],
  bssEntries: WindowsNativeBssEntry[]
): WindowsWifiNetwork[] {
  if (bssEntries.length === 0) {
    return networks;
  }

  const byBssid = new Map<string, WindowsNativeBssEntry>();

  for (const entry of bssEntries) {
    const key = normalizeMac(entry.bssid);
    if (key) {
      byBssid.set(key, entry);
    }
  }

  return networks.map((network) => {
    const entry = byBssid.get(normalizeMac(network.bssid) ?? '');
    if (!entry) {
      return network;
    }

    return {
      ...network,
      native_bss: entry.native_bss,
      raw: {
        ...network.raw,
        'Native BSS RSSI': formatNullableNumber(entry.native_bss.rssi_dbm),
        'Native BSS Link Quality': formatNullableNumber(entry.native_bss.link_quality),
        'Native BSS Center Frequency KHz': formatNullableNumber(entry.native_bss.center_frequency_khz),
        'Native BSS IE Names': entry.native_bss.information_elements.names.join(', ')
      }
    };
  });
}

function normalizeMac(input: string | null): string | null {
  if (!input) {
    return null;
  }

  return input.trim().replace(/-/g, ':').toLowerCase();
}

function formatNullableNumber(value: number | null): string {
  return value === null ? '' : String(value);
}
