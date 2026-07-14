import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import type {
  LocalNetworkDevice,
  LocalNetworkExposureCheck,
  LocalNetworkScanMode,
  LocalNetworkScanResult,
  WindowsWifiSnapshot
} from './types';

const execFileAsync = promisify(execFile);
const POWERSHELL = process.platform === 'win32' ? 'powershell.exe' : 'pwsh';

export interface LocalNetworkScanOptions {
  mode: LocalNetworkScanMode;
  snapshot?: WindowsWifiSnapshot | null;
  commandRunner?: (command: string, args: string[], timeoutMs: number) => Promise<{ stdout: string; stderr: string }>;
  now?: Date;
}

interface RawNeighbor {
  IPAddress?: unknown;
  LinkLayerAddress?: unknown;
  State?: unknown;
  InterfaceAlias?: unknown;
}

export async function scanLocalNetwork(options: LocalNetworkScanOptions): Promise<LocalNetworkScanResult> {
  const now = options.now ?? new Date();
  const runner = options.commandRunner ?? runCommand;
  const snapshot = options.snapshot ?? null;
  const gateway = cleanIp(snapshot?.default_gateway ?? null);
  const localIp = firstUsableIp(snapshot?.ipv4_addresses ?? []);
  const localMac = cleanMac(snapshot?.physical_address ?? null);
  const prefix = localIp ? ipv4Prefix24(localIp) : gateway ? ipv4Prefix24(gateway) : null;

  try {
    const neighbors = await readNeighborTable(runner);
    const devicesByIp = new Map<string, LocalNetworkDevice>();

    for (const neighbor of neighbors) {
      const ipAddress = cleanIp(asString(neighbor.IPAddress));
      if (!ipAddress || !isUsefulLanAddress(ipAddress, prefix)) {
        continue;
      }

      const macAddress = cleanMac(asString(neighbor.LinkLayerAddress));
      const state = normalizeNeighborState(asString(neighbor.State));
      devicesByIp.set(ipAddress, {
        ip_address: ipAddress,
        mac_address: macAddress,
        hostname: null,
        latency_ms: null,
        state,
        interface_alias: asString(neighbor.InterfaceAlias),
        is_gateway: gateway !== null && ipAddress === gateway,
        source: 'net_neighbor',
        notes: []
      });
    }

    if (gateway && !devicesByIp.has(gateway)) {
      devicesByIp.set(gateway, {
        ip_address: gateway,
        mac_address: null,
        hostname: null,
        latency_ms: null,
        state: 'unknown',
        interface_alias: snapshot?.interface_name ?? null,
        is_gateway: true,
        source: 'net_neighbor',
        notes: ['Gateway from current Wi-Fi snapshot; not present in neighbor table yet.']
      });
    }

    if (options.mode === 'poll' || options.mode === 'active') {
      await applyReachabilityPoll([...devicesByIp.values()], runner);
    }
    if (options.mode === 'active') {
      await applyDirectDeviceInfoPoll([...devicesByIp.values()], runner);
    }

    const devices = [...devicesByIp.values()].sort(compareLocalDevices);
    const activeCount = devices.filter((device) => device.state === 'active').length;
    const staleCount = devices.filter((device) => device.state === 'stale').length;

    return {
      schema: 'monitor.local_network_scan.v1',
      ts_utc: now.toISOString(),
      mode: options.mode,
      status: 'saved',
      local_ip: localIp,
      local_mac: localMac,
      gateway,
      prefix,
      device_count: devices.length,
      active_count: activeCount,
      stale_count: staleCount,
      devices,
      exposure_checks: buildLocalNetworkExposureChecks(devices, options.mode, localIp, gateway),
      error: null
    };
  } catch (error: unknown) {
    return {
      schema: 'monitor.local_network_scan.v1',
      ts_utc: now.toISOString(),
      mode: options.mode,
      status: 'failed',
      local_ip: localIp,
      local_mac: localMac,
      gateway,
      prefix,
      device_count: 0,
      active_count: 0,
      stale_count: 0,
      devices: [],
      exposure_checks: [],
      error: error instanceof Error ? error.message : String(error)
    };
  }
}

async function readNeighborTable(
  runner: NonNullable<LocalNetworkScanOptions['commandRunner']>
): Promise<RawNeighbor[]> {
  const script = [
    '$items = Get-NetNeighbor -AddressFamily IPv4 -ErrorAction Stop |',
    'Where-Object { $_.IPAddress -and $_.IPAddress -notlike "224.*" -and $_.IPAddress -ne "255.255.255.255" } |',
    'Select-Object IPAddress,LinkLayerAddress,State,InterfaceAlias;',
    '$items | ConvertTo-Json -Depth 3'
  ].join(' ');
  const { stdout } = await runner(POWERSHELL, ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', script], 8_000);
  const trimmed = stdout.trim();
  if (!trimmed) {
    return [];
  }

  const parsed = JSON.parse(trimmed) as RawNeighbor | RawNeighbor[];
  return Array.isArray(parsed) ? parsed : [parsed];
}

async function applyReachabilityPoll(
  devices: LocalNetworkDevice[],
  runner: NonNullable<LocalNetworkScanOptions['commandRunner']>
): Promise<void> {
  const targets = devices
    .map((device) => device.ip_address)
    .filter((ipAddress) => isIpv4Address(ipAddress))
    .slice(0, 96);
  if (targets.length === 0) {
    return;
  }

  const quotedTargets = targets.map((target) => `'${target.replace(/'/g, "''")}'`).join(',');
  const script = [
    `$targets = @(${quotedTargets});`,
    '$targets | ForEach-Object {',
    '$probe = Test-Connection -ComputerName $_ -Count 1 -TimeoutSeconds 1 -ErrorAction SilentlyContinue | Select-Object -First 1;',
    '$ok = $null -ne $probe;',
    '$latency = if ($probe -and $probe.ResponseTime -ne $null) { [int]$probe.ResponseTime } else { $null };',
    '[pscustomobject]@{ IPAddress = $_; Reachable = $ok; LatencyMs = $latency }',
    '} | ConvertTo-Json -Depth 3'
  ].join(' ');
  const { stdout } = await runner(POWERSHELL, ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', script], 20_000);
  const parsed = parseReachability(stdout);
  const byIp = new Map(parsed.map((entry) => [entry.ipAddress, entry]));

  for (const device of devices) {
    const reachability = byIp.get(device.ip_address);
    if (reachability?.reachable === true) {
      device.state = 'active';
      device.source = 'reachability_probe';
      device.latency_ms = reachability.latencyMs ?? device.latency_ms;
      device.notes = [...device.notes, 'Responded to a reachability poll for an already visible neighbor IP.'];
    } else if (reachability?.reachable === false && device.state === 'active') {
      device.state = 'stale';
      device.notes = [...device.notes, 'Neighbor cache said reachable, but the reachability poll did not answer.'];
    }
  }
}

async function applyDirectDeviceInfoPoll(
  devices: LocalNetworkDevice[],
  runner: NonNullable<LocalNetworkScanOptions['commandRunner']>
): Promise<void> {
  const targets = devices
    .map((device) => device.ip_address)
    .filter((ipAddress) => isIpv4Address(ipAddress))
    .slice(0, 96);
  if (targets.length === 0) {
    return;
  }

  const quotedTargets = targets.map((target) => `'${target.replace(/'/g, "''")}'`).join(',');
  const script = [
    `$targets = @(${quotedTargets});`,
    '$targets | ForEach-Object {',
    '$hostName = $null;',
    'try { $entry = [System.Net.Dns]::GetHostEntry($_); if ($entry -and $entry.HostName) { $hostName = $entry.HostName } } catch { };',
    '[pscustomobject]@{ IPAddress = $_; Hostname = $hostName }',
    '} | ConvertTo-Json -Depth 3'
  ].join(' ');
  const { stdout } = await runner(POWERSHELL, ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', script], 20_000);
  const hostnames = parseHostnames(stdout);
  const byIp = new Map(hostnames.map((entry) => [entry.ipAddress, entry.hostname]));

  for (const device of devices) {
    const hostname = byIp.get(device.ip_address);
    if (hostname) {
      device.hostname = hostname;
      device.source = 'direct_probe';
      device.notes = [...device.notes, 'Resolved hostname during active direct poll.'];
    }
  }
}

function parseReachability(stdout: string): Array<{ ipAddress: string; reachable: boolean; latencyMs: number | null }> {
  const trimmed = stdout.trim();
  if (!trimmed) {
    return [];
  }

  const parsed = JSON.parse(trimmed) as Array<{ IPAddress?: unknown; Reachable?: unknown; LatencyMs?: unknown }> | { IPAddress?: unknown; Reachable?: unknown; LatencyMs?: unknown };
  const rows = Array.isArray(parsed) ? parsed : [parsed];
  return rows
    .map((row) => ({
      ipAddress: cleanIp(asString(row.IPAddress)),
      reachable: row.Reachable === true,
      latencyMs: typeof row.LatencyMs === 'number' && Number.isFinite(row.LatencyMs) ? Math.max(0, Math.round(row.LatencyMs)) : null
    }))
    .filter((row): row is { ipAddress: string; reachable: boolean; latencyMs: number | null } => Boolean(row.ipAddress));
}

function parseHostnames(stdout: string): Array<{ ipAddress: string; hostname: string | null }> {
  const trimmed = stdout.trim();
  if (!trimmed) {
    return [];
  }

  const parsed = JSON.parse(trimmed) as Array<{ IPAddress?: unknown; Hostname?: unknown }> | { IPAddress?: unknown; Hostname?: unknown };
  const rows = Array.isArray(parsed) ? parsed : [parsed];
  return rows
    .map((row) => ({
      ipAddress: cleanIp(asString(row.IPAddress)),
      hostname: cleanHostname(asString(row.Hostname))
    }))
    .filter((row): row is { ipAddress: string; hostname: string | null } => Boolean(row.ipAddress));
}

function buildLocalNetworkExposureChecks(
  devices: LocalNetworkDevice[],
  mode: LocalNetworkScanMode,
  localIp: string | null,
  gateway: string | null
): LocalNetworkExposureCheck[] {
  const unknownMacCount = devices.filter((device) => !device.mac_address).length;
  const staleCount = devices.filter((device) => device.state === 'stale').length;
  const gatewayKnown = Boolean(gateway && devices.some((device) => device.ip_address === gateway));
  const visibility = scanVisibilityProfileForMode(mode);

  return [
    {
      id: 'local_network.scan_visibility',
      label: 'Scanner visibility posture',
      status: visibility.status,
      summary: visibility.summary,
      evidence: [
        `mode=${mode}`,
        `footprint=${visibility.footprint}`,
        `expected_logs=${visibility.expectedLogs}`
      ]
    },
    {
      id: 'local_network.inventory_visibility',
      label: 'Local network inventory visibility',
      status: devices.length > 0 ? 'info' : 'watch',
      summary:
        devices.length > 0
          ? `${devices.length} local IPv4 neighbor(s) are visible from this client.`
          : 'No local IPv4 neighbors are visible yet; refresh Wi-Fi/client state or run poll mode.',
      evidence: [`local_ip=${localIp ?? 'unknown'}`, `gateway=${gateway ?? 'unknown'}`, `mode=${mode}`]
    },
    {
      id: 'local_network.gateway_presence',
      label: 'Gateway presence',
      status: gatewayKnown ? 'info' : 'review',
      summary: gatewayKnown
        ? 'Current gateway is present in the observed local-neighbor set.'
        : 'Current gateway was not confirmed in the neighbor set; verify adapter IP/gateway state.',
      evidence: [`gateway=${gateway ?? 'unknown'}`]
    },
    {
      id: 'local_network.stale_neighbors',
      label: 'Stale or unresolved neighbors',
      status: staleCount > 0 || unknownMacCount > 0 ? 'watch' : 'info',
      summary: `${staleCount} stale neighbor(s), ${unknownMacCount} without MAC evidence.`,
      evidence: [`stale=${staleCount}`, `unknown_mac=${unknownMacCount}`]
    }
  ];
}

function scanVisibilityProfileForMode(mode: LocalNetworkScanMode): {
  status: LocalNetworkExposureCheck['status'];
  footprint: string;
  expectedLogs: string;
  summary: string;
} {
  if (mode === 'active') {
    return {
      status: 'review',
      footprint: 'direct_icmp_and_name_resolution',
      expectedLogs: 'source_ip_mac_dns_or_host_logs',
      summary:
        'Active scan sends direct reachability probes to already visible LAN neighbors and may create DNS/name-resolution or endpoint logs.'
    };
  }

  if (mode === 'poll') {
    return {
      status: 'watch',
      footprint: 'ordinary_host_reachability',
      expectedLogs: 'source_ip_mac_possible_neighbor_or_icmp_logs',
      summary:
        'Partial visibility mode uses ordinary reachability checks for already visible LAN neighbors; monitoring may see this client as a normal PC.'
    };
  }

  return {
    status: 'info',
    footprint: 'local_cache_only',
    expectedLogs: 'no_monitor_probe_traffic',
    summary:
      'Passive mode reads local Windows neighbor/cache telemetry only; Monitor sends no LAN probe traffic, but normal OS/network activity can still be logged.'
  };
}

async function runCommand(command: string, args: string[], timeoutMs: number): Promise<{ stdout: string; stderr: string }> {
  const result = await execFileAsync(command, args, {
    timeout: timeoutMs,
    windowsHide: true,
    maxBuffer: 2 * 1024 * 1024
  });
  return {
    stdout: result.stdout,
    stderr: result.stderr
  };
}

function normalizeNeighborState(value: string | null): LocalNetworkDevice['state'] {
  const normalized = value?.trim().toLowerCase() ?? '';
  if (normalized === 'reachable' || normalized === 'permanent') {
    return 'active';
  }
  if (normalized === 'stale' || normalized === 'delay' || normalized === 'probe') {
    return 'stale';
  }
  return 'unknown';
}

function cleanHostname(value: string | null): string | null {
  const trimmed = value?.trim().replace(/\s+/g, ' ') ?? '';
  if (!trimmed || trimmed.length > 253) {
    return null;
  }

  return trimmed;
}

function compareLocalDevices(left: LocalNetworkDevice, right: LocalNetworkDevice): number {
  if (left.is_gateway !== right.is_gateway) {
    return left.is_gateway ? -1 : 1;
  }

  return ipv4ToNumber(left.ip_address) - ipv4ToNumber(right.ip_address);
}

function firstUsableIp(values: string[]): string | null {
  for (const value of values) {
    const cleaned = cleanIp(value);
    if (cleaned && isIpv4Address(cleaned) && !cleaned.startsWith('169.254.')) {
      return cleaned;
    }
  }

  return null;
}

function isUsefulLanAddress(value: string, prefix: string | null): boolean {
  if (!isIpv4Address(value) || value === '0.0.0.0' || value.startsWith('127.')) {
    return false;
  }

  return !prefix || value.startsWith(`${prefix}.`);
}

function ipv4Prefix24(value: string): string | null {
  const parts = value.split('.');
  return parts.length === 4 ? parts.slice(0, 3).join('.') : null;
}

function ipv4ToNumber(value: string): number {
  return value.split('.').reduce((total, part) => total * 256 + Number(part), 0);
}

function isIpv4Address(value: string): boolean {
  const parts = value.split('.');
  return parts.length === 4 && parts.every((part) => /^\d{1,3}$/.test(part) && Number(part) >= 0 && Number(part) <= 255);
}

function cleanIp(value: string | null): string | null {
  const trimmed = value?.trim() ?? '';
  return isIpv4Address(trimmed) ? trimmed : null;
}

function cleanMac(value: string | null): string | null {
  const trimmed = value?.trim() ?? '';
  const hex = trimmed.replace(/[^a-fA-F0-9]/g, '').toLowerCase();
  if (hex.length !== 12 || hex === '000000000000') {
    return null;
  }

  return hex.match(/.{2}/g)?.join(':') ?? null;
}

function asString(value: unknown): string | null {
  return typeof value === 'string' && value.trim() ? value.trim() : null;
}
