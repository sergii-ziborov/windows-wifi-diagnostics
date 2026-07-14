import type { WindowsWifiSnapshot } from '../../collector/types';

interface RawNetIpConfiguration {
  InterfaceAlias?: string;
  InterfaceIndex?: number;
  InterfaceGuid?: string;
  InterfaceDescription?: string;
  MacAddress?: string;
  Status?: string;
  IPv4Address?: RawIpAddress | RawIpAddress[] | string | string[];
  IPv6Address?: RawIpAddress | RawIpAddress[] | string | string[];
  IPv4DefaultGateway?: RawGateway | RawGateway[] | string | string[];
  IPv6DefaultGateway?: RawGateway | RawGateway[] | string | string[];
  DNSServer?: RawDnsServer | string | string[];
}

interface RawIpAddress {
  IPAddress?: string;
}

interface RawGateway {
  NextHop?: string;
}

interface RawDnsServer {
  ServerAddresses?: string | string[];
}

export function buildNetIpConfigurationScript(): string {
  return [
    'Get-NetIPConfiguration | ForEach-Object {',
    '$adapter = Get-NetAdapter -InterfaceIndex $_.InterfaceIndex -ErrorAction SilentlyContinue;',
    '[PSCustomObject]@{',
    'InterfaceAlias = $_.InterfaceAlias;',
    'InterfaceIndex = $_.InterfaceIndex;',
    'InterfaceGuid = $adapter.InterfaceGuid;',
    'InterfaceDescription = if ($_.InterfaceDescription) { $_.InterfaceDescription } else { $adapter.InterfaceDescription };',
    'MacAddress = $adapter.MacAddress;',
    'Status = $adapter.Status;',
    'IPv4Address = @($_.IPv4Address | ForEach-Object { $_.IPAddress });',
    'IPv6Address = @($_.IPv6Address | ForEach-Object { $_.IPAddress });',
    'IPv4DefaultGateway = @($_.IPv4DefaultGateway | ForEach-Object { $_.NextHop });',
    'IPv6DefaultGateway = @($_.IPv6DefaultGateway | ForEach-Object { $_.NextHop });',
    'DNSServer = @($_.DNSServer.ServerAddresses)',
    '}',
    '} |',
    'ConvertTo-Json -Depth 6 -Compress'
  ].join(' ');
}

export function enrichSnapshotsWithIpConfiguration(
  snapshots: WindowsWifiSnapshot[],
  jsonOutput: string
): WindowsWifiSnapshot[] {
  const configs = parseNetIpConfigurations(jsonOutput);
  if (configs.length === 0) {
    return snapshots;
  }

  return snapshots.map((snapshot) => {
    const config = configs.find((candidate) => matchesSnapshot(candidate, snapshot));
    if (!config) {
      return snapshot;
    }

    return {
      ...snapshot,
      ipv4_addresses: ipAddresses(config.IPv4Address),
      ipv6_addresses: ipAddresses(config.IPv6Address).filter((address) => !address.toLowerCase().startsWith('fe80:')),
      default_gateway: firstString([
        ...gateways(config.IPv4DefaultGateway),
        ...gateways(config.IPv6DefaultGateway)
      ]),
      dns_servers: dnsServers(config.DNSServer)
    };
  });
}

function parseNetIpConfigurations(jsonOutput: string): RawNetIpConfiguration[] {
  const trimmed = jsonOutput.trim();
  if (!trimmed) {
    return [];
  }

  try {
    const parsed = JSON.parse(trimmed) as RawNetIpConfiguration | RawNetIpConfiguration[] | null;
    return Array.isArray(parsed) ? parsed : parsed ? [parsed] : [];
  } catch {
    return [];
  }
}

function matchesSnapshot(config: RawNetIpConfiguration, snapshot: WindowsWifiSnapshot): boolean {
  const alias = normalizeKey(config.InterfaceAlias);
  const description = normalizeKey(config.InterfaceDescription);
  const configGuid = normalizeGuid(config.InterfaceGuid);
  const snapshotGuid = normalizeGuid(snapshot.interface_guid);
  const configMac = normalizeMac(config.MacAddress);
  const snapshotMac = normalizeMac(snapshot.physical_address);

  return Boolean(
    (configGuid && snapshotGuid && configGuid === snapshotGuid) ||
      (configMac && snapshotMac && configMac === snapshotMac) ||
      (alias && alias === normalizeKey(snapshot.interface_name)) ||
      (description && description === normalizeKey(snapshot.adapter))
  );
}

function ipAddresses(value: RawIpAddress | RawIpAddress[] | string | string[] | undefined): string[] {
  return uniqueStrings(arrayOf(value).map((entry) => cleanIp(typeof entry === 'string' ? entry : entry?.IPAddress)));
}

function gateways(value: RawGateway | RawGateway[] | string | string[] | undefined): string[] {
  return uniqueStrings(arrayOf(value).map((entry) => cleanIp(typeof entry === 'string' ? entry : entry?.NextHop)));
}

function dnsServers(value: RawDnsServer | string | string[] | undefined): string[] {
  return uniqueStrings(arrayOf(typeof value === 'string' || Array.isArray(value) ? value : value?.ServerAddresses).map(cleanIp));
}

function firstString(values: string[]): string | null {
  return values[0] ?? null;
}

function arrayOf<T>(value: T | T[] | undefined): T[] {
  if (value === undefined || value === null) {
    return [];
  }

  return Array.isArray(value) ? value : [value];
}

function cleanIp(value: unknown): string | null {
  if (typeof value !== 'string') {
    return null;
  }

  const trimmed = value.trim();
  return trimmed && trimmed !== '::' && trimmed !== '0.0.0.0' ? trimmed : null;
}

function normalizeKey(value: string | null | undefined): string {
  return value?.trim().toLowerCase() ?? '';
}

function normalizeGuid(value: string | null | undefined): string {
  return value?.trim().replace(/[{}]/g, '').toLowerCase() ?? '';
}

function normalizeMac(value: string | null | undefined): string {
  return value?.trim().replace(/-/g, ':').toLowerCase() ?? '';
}

function uniqueStrings(values: Array<string | null | undefined>): string[] {
  const output: string[] = [];
  const seen = new Set<string>();

  for (const value of values) {
    if (!value || seen.has(value)) {
      continue;
    }

    seen.add(value);
    output.push(value);
  }

  return output;
}
