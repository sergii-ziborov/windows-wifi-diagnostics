import { enrichMacAddress } from '../../collector/macLookup';
import { ensureNetworkSecurityAssessment } from '../../collector/wifiSecurity';
import type { EventContext, WindowsWifiNetwork, WindowsWifiSnapshot } from '../../collector/types';

export function parseNetshWlanInterfaces(
  output: string,
  context: EventContext,
  now = new Date()
): WindowsWifiSnapshot[] {
  const interfaces = splitInterfaceBlocks(output);

  return interfaces.map((raw) => {
    const fields = parseKeyValueLines(raw);

    return {
      schema: 'wifi.windows_baseline.v1',
      event_type: 'windows_wifi_snapshot',
      ts_utc: now.toISOString(),
      source: 'baseline',
      run_id: context.runId,
      host_id: context.hostId,
      adapter: value(fields, 'Description'),
      interface_name: value(fields, 'Name'),
      interface_guid: value(fields, 'GUID'),
      physical_address: normalizeMac(value(fields, 'Physical address')),
      state: value(fields, 'State'),
      ssid: value(fields, 'SSID'),
      bssid: normalizeMac(value(fields, 'AP BSSID')),
      band: value(fields, 'Band'),
      channel: parseNumber(value(fields, 'Channel')),
      radio_type: value(fields, 'Radio type'),
      authentication: value(fields, 'Authentication'),
      cipher: value(fields, 'Cipher'),
      receive_mbps: parseNumber(value(fields, 'Receive rate (Mbps)')),
      transmit_mbps: parseNumber(value(fields, 'Transmit rate (Mbps)')),
      signal_percent: parsePercent(value(fields, 'Signal')),
      rssi_dbm: parseNumber(value(fields, 'Rssi')),
      raw: fields
    };
  });
}

export function parseNetshWlanNetworks(
  output: string,
  context: EventContext,
  now = new Date()
): WindowsWifiNetwork[] {
  const networks: WindowsWifiNetwork[] = [];
  let interfaceName: string | null = null;
  let currentSsid: string | null = null;
  let ssidFields: Record<string, string> = {};
  let currentBssid: string | null = null;
  let bssidFields: Record<string, string> = {};

  const flushBssid = () => {
    if (!currentBssid) {
      return;
    }

    const raw = { ...ssidFields, BSSID: currentBssid, ...bssidFields };
    const bssid = normalizeMac(currentBssid);
    networks.push(ensureNetworkSecurityAssessment({
      schema: 'wifi.windows_baseline.v1',
      event_type: 'windows_wifi_network',
      ts_utc: now.toISOString(),
      source: 'baseline',
      run_id: context.runId,
      host_id: context.hostId,
      interface_name: interfaceName,
      ssid: currentSsid,
      network_type: value(ssidFields, 'Network type'),
      authentication: value(ssidFields, 'Authentication'),
      encryption: value(ssidFields, 'Encryption'),
      bssid,
      signal_percent: parsePercent(value(bssidFields, 'Signal')),
      radio_type: value(bssidFields, 'Radio type'),
      band: value(bssidFields, 'Band'),
      channel: parseNumber(value(bssidFields, 'Channel')),
      basic_rates_mbps: parseNumberList(value(bssidFields, 'Basic rates (Mbps)')),
      other_rates_mbps: parseNumberList(value(bssidFields, 'Other rates (Mbps)')),
      mac_enrichment: enrichMacAddress(bssid, currentSsid),
      raw
    }));
  };

  for (const line of output.split(/\r?\n/)) {
    const interfaceMatch = line.match(/^\s*Interface name\s*:\s*(.*?)\s*$/);
    if (interfaceMatch) {
      interfaceName = interfaceMatch[1].trim() || null;
      continue;
    }

    const ssidMatch = line.match(/^\s*SSID\s+\d+\s*:\s*(.*?)\s*$/);
    if (ssidMatch) {
      flushBssid();
      currentSsid = ssidMatch[1].trim() || null;
      ssidFields = {};
      currentBssid = null;
      bssidFields = {};
      continue;
    }

    const bssidMatch = line.match(/^\s*BSSID\s+\d+\s*:\s*(.*?)\s*$/);
    if (bssidMatch) {
      flushBssid();
      currentBssid = bssidMatch[1].trim() || null;
      bssidFields = {};
      continue;
    }

    const keyValue = parseKeyValueLine(line);
    if (!keyValue) {
      continue;
    }

    const [key, parsedValue] = keyValue;
    if (currentBssid) {
      bssidFields[key] = parsedValue;
    } else if (currentSsid !== null) {
      ssidFields[key] = parsedValue;
    }
  }

  flushBssid();
  return networks;
}

function splitInterfaceBlocks(output: string): string[][] {
  const blocks: string[][] = [];
  let current: string[] = [];

  for (const line of output.split(/\r?\n/)) {
    if (/^\s*Name\s*:/.test(line)) {
      if (current.length > 0) {
        blocks.push(current);
      }
      current = [line];
      continue;
    }

    if (current.length > 0) {
      current.push(line);
    }
  }

  if (current.length > 0) {
    blocks.push(current);
  }

  return blocks;
}

function parseKeyValueLines(lines: string[]): Record<string, string> {
  const fields: Record<string, string> = {};

  for (const line of lines) {
    const parsed = parseKeyValueLine(line);
    if (!parsed) {
      continue;
    }

    fields[parsed[0]] = parsed[1];
  }

  return fields;
}

function parseKeyValueLine(line: string): [string, string] | null {
  const match = line.match(/^\s*([^:]+?)\s*:\s*(.*?)\s*$/);
  if (!match) {
    return null;
  }

  return [match[1].trim(), match[2].trim()];
}

function value(fields: Record<string, string>, key: string): string | null {
  const found = fields[key];
  return found && found.length > 0 ? found : null;
}

function parseNumber(input: string | null): number | null {
  if (!input) {
    return null;
  }

  const match = input.match(/-?\d+(?:\.\d+)?/);
  if (!match) {
    return null;
  }

  const parsed = Number(match[0]);
  return Number.isFinite(parsed) ? parsed : null;
}

function parsePercent(input: string | null): number | null {
  return parseNumber(input);
}

function parseNumberList(input: string | null): number[] {
  if (!input) {
    return [];
  }

  return input
    .match(/-?\d+(?:\.\d+)?/g)
    ?.map((value) => Number(value))
    .filter((parsed) => Number.isFinite(parsed)) ?? [];
}

function normalizeMac(input: string | null): string | null {
  if (!input) {
    return null;
  }

  return input.trim().replace(/-/g, ':').toLowerCase();
}
