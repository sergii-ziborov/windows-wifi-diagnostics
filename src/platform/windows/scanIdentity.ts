import { createHash } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { runPowerShell } from './powershell';
import type {
  ScanIdentityChangeRequest,
  ScanIdentityChangeResult,
  ScanIdentityState
} from '../../collector/types';

interface RawScanIdentityState {
  isAdmin?: unknown;
  computerName?: unknown;
  interfaceName?: unknown;
  adapterName?: unknown;
  macAddress?: unknown;
  activeMacOverride?: unknown;
  error?: unknown;
}

interface StoredScanIdentityOriginals {
  schema: 'monitor.scan_identity_originals.v1';
  saved_at_utc: string;
  interface_name: string | null;
  adapter_name: string | null;
  original_computer_name: string | null;
  original_mac_address: string | null;
  original_mac_override: string | null;
}

type ScanIdentityApplyOptions = ScanIdentityChangeRequest & {
  clearMacAddress?: boolean;
};

const DEFAULT_SCAN_IDENTITY_NAME = 'RADIOCHRON-SCOUT';
const DEFAULT_STATE_FILE = resolve('data', 'scan-identity-originals.json');

export async function getWindowsScanIdentityState(options: {
  interfaceName?: string | null;
  adapterName?: string | null;
  stateFile?: string | null;
} = {}): Promise<ScanIdentityState> {
  if (process.platform !== 'win32') {
    return unsupportedState('Scan identity changes are only available on Windows.');
  }

  const stored = await readStoredOriginals(options.stateFile);
  try {
    const { stdout } = await runPowerShell(buildReadStateScript(options), 10_000);
    return stateFromRaw(parseRawState(stdout), stored);
  } catch (error) {
    return {
      ...unsupportedState(error instanceof Error ? error.message : String(error)),
      supported: true
    };
  }
}

export async function applyWindowsScanIdentity(request: ScanIdentityChangeRequest & {
  stateFile?: string | null;
}): Promise<ScanIdentityChangeResult> {
  const before = await getWindowsScanIdentityState(request);
  const stored = await ensureStoredOriginals(before, request.stateFile);
  const requestedComputerName = normalizeComputerName(request.computerName) ?? before.suggested_computer_name;
  const requestedMac = normalizeMacAddress(request.macAddress, true) ?? before.suggested_mac_address;

  if (!before.supported || before.error) {
    return changeResultFromState('apply', before, false, false, '', '', '', before.error ?? 'Scan identity is unavailable.');
  }
  if (before.requires_admin) {
    return changeResultFromState('apply', before, false, false, '', '', '', 'Administrator rights are required to apply scan identity.');
  }

  const changedComputerName = Boolean(requestedComputerName && requestedComputerName !== before.current_computer_name);
  const changedMacAddress = Boolean(requestedMac && normalizeMacAddress(requestedMac) !== normalizeMacAddress(before.current_mac_address));
  const script = buildApplyScript({
    ...request,
    computerName: requestedComputerName,
    macAddress: requestedMac
  });

  try {
    const { stdout, stderr } = await runPowerShell(script, request.restartAdapter === false ? 20_000 : 35_000);
    const after = await getWindowsScanIdentityState(request);
    return {
      ...after,
      stored_original_computer_name: stored.original_computer_name,
      stored_original_mac_address: stored.original_mac_address,
      action: 'apply',
      changed_computer_name: changedComputerName,
      changed_mac_address: changedMacAddress,
      command: 'scan-identity apply',
      stdout,
      stderr
    };
  } catch (error) {
    return changeResultFromState(
      'apply',
      await getWindowsScanIdentityState(request),
      changedComputerName,
      changedMacAddress,
      'scan-identity apply',
      '',
      '',
      error instanceof Error ? error.message : String(error)
    );
  }
}

export async function restoreWindowsScanIdentity(request: ScanIdentityChangeRequest & {
  stateFile?: string | null;
} = {}): Promise<ScanIdentityChangeResult> {
  const before = await getWindowsScanIdentityState(request);
  const stored = await readStoredOriginals(request.stateFile);
  const restoreComputerName = normalizeComputerName(request.computerName) ?? stored?.original_computer_name ?? null;
  const requestedRestoreMac = normalizeMacAddress(request.macAddress);
  const restoreMac = requestedRestoreMac ?? stored?.original_mac_override ?? stored?.original_mac_address ?? null;
  const clearMacAddress = !requestedRestoreMac && Boolean(stored) && !stored?.original_mac_override;

  if (!before.supported || before.error) {
    return changeResultFromState('restore', before, false, false, '', '', '', before.error ?? 'Scan identity is unavailable.');
  }
  if (before.requires_admin) {
    return changeResultFromState('restore', before, false, false, '', '', '', 'Administrator rights are required to restore scan identity.');
  }
  if (!restoreComputerName && !restoreMac && !clearMacAddress) {
    return changeResultFromState('restore', before, false, false, '', '', '', 'No stored scan identity originals were found.');
  }

  const changedComputerName = Boolean(restoreComputerName && restoreComputerName !== before.current_computer_name);
  const changedMacAddress = clearMacAddress || Boolean(restoreMac && normalizeMacAddress(restoreMac) !== normalizeMacAddress(before.current_mac_address));
  const script = buildApplyScript({
    ...request,
    computerName: restoreComputerName,
    macAddress: restoreMac,
    clearMacAddress
  });

  try {
    const { stdout, stderr } = await runPowerShell(script, request.restartAdapter === false ? 20_000 : 35_000);
    const after = await getWindowsScanIdentityState(request);
    return {
      ...after,
      action: 'restore',
      changed_computer_name: changedComputerName,
      changed_mac_address: changedMacAddress,
      command: 'scan-identity restore',
      stdout,
      stderr
    };
  } catch (error) {
    return changeResultFromState(
      'restore',
      await getWindowsScanIdentityState(request),
      changedComputerName,
      changedMacAddress,
      'scan-identity restore',
      '',
      '',
      error instanceof Error ? error.message : String(error)
    );
  }
}

function buildReadStateScript(options: { interfaceName?: string | null; adapterName?: string | null }): string {
  const interfaceName = psString(options.interfaceName ?? null);
  const adapterName = psString(options.adapterName ?? null);
  return [
    '$ErrorActionPreference = "Stop";',
    '$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent());',
    '$isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator);',
    `$interfaceName = ${interfaceName};`,
    `$adapterName = ${adapterName};`,
    '$adapter = $null;',
    'if ($interfaceName) { $adapter = Get-NetAdapter -Name $interfaceName -ErrorAction SilentlyContinue | Select-Object -First 1; }',
    'if (-not $adapter -and $adapterName) { $adapter = Get-NetAdapter | Where-Object { $_.InterfaceDescription -eq $adapterName -or $_.Name -eq $adapterName } | Select-Object -First 1; }',
    'if (-not $adapter) { $adapter = Get-NetAdapter | Where-Object { $_.NdisPhysicalMedium -eq 9 -or $_.Name -like "*Wi-Fi*" -or $_.InterfaceDescription -like "*Wireless*" } | Select-Object -First 1; }',
    '$override = $null;',
    'if ($adapter) {',
    '  $prop = Get-NetAdapterAdvancedProperty -Name $adapter.Name -RegistryKeyword NetworkAddress -ErrorAction SilentlyContinue | Select-Object -First 1;',
    '  if ($prop) { $override = [string]$prop.RegistryValue; }',
    '}',
    '[pscustomobject]@{',
    '  isAdmin = $isAdmin;',
    '  computerName = $env:COMPUTERNAME;',
    '  interfaceName = if ($adapter) { $adapter.Name } else { $null };',
    '  adapterName = if ($adapter) { $adapter.InterfaceDescription } else { $null };',
    '  macAddress = if ($adapter) { $adapter.MacAddress } else { $null };',
    '  activeMacOverride = $override;',
    '  error = if ($adapter) { $null } else { "Wi-Fi adapter was not found." }',
    '} | ConvertTo-Json -Depth 3'
  ].join(' ');
}

function buildApplyScript(options: ScanIdentityApplyOptions): string {
  const interfaceName = psString(options.interfaceName ?? null);
  const adapterName = psString(options.adapterName ?? null);
  const computerName = psString(normalizeComputerName(options.computerName) ?? null);
  const macAddress = psString(normalizeMacAddress(options.macAddress)?.replace(/:/g, '') ?? null);
  const clearMacAddress = options.clearMacAddress === true ? '$true' : '$false';
  const restartAdapter = options.restartAdapter === false ? '$false' : '$true';
  return [
    '$ErrorActionPreference = "Stop";',
    `$interfaceName = ${interfaceName};`,
    `$adapterName = ${adapterName};`,
    `$newComputerName = ${computerName};`,
    `$newMac = ${macAddress};`,
    `$clearMac = ${clearMacAddress};`,
    `$restartAdapter = ${restartAdapter};`,
    '$adapter = $null;',
    'if ($interfaceName) { $adapter = Get-NetAdapter -Name $interfaceName -ErrorAction SilentlyContinue | Select-Object -First 1; }',
    'if (-not $adapter -and $adapterName) { $adapter = Get-NetAdapter | Where-Object { $_.InterfaceDescription -eq $adapterName -or $_.Name -eq $adapterName } | Select-Object -First 1; }',
    'if (-not $adapter) { $adapter = Get-NetAdapter | Where-Object { $_.NdisPhysicalMedium -eq 9 -or $_.Name -like "*Wi-Fi*" -or $_.InterfaceDescription -like "*Wireless*" } | Select-Object -First 1; }',
    'if (-not $adapter) { throw "Wi-Fi adapter was not found." }',
    '$macTouched = $false;',
    'if ($clearMac) {',
    '  Reset-NetAdapterAdvancedProperty -Name $adapter.Name -RegistryKeyword NetworkAddress -NoRestart -ErrorAction Stop;',
    '  $macTouched = $true;',
    '} elseif ($newMac) {',
    '  Set-NetAdapterAdvancedProperty -Name $adapter.Name -RegistryKeyword NetworkAddress -RegistryValue $newMac -NoRestart -ErrorAction Stop;',
    '  $macTouched = $true;',
    '}',
    'if ($macTouched -and $restartAdapter) {',
    '  Disable-NetAdapter -Name $adapter.Name -Confirm:$false -ErrorAction Stop;',
    '  Start-Sleep -Seconds 2;',
    '  Enable-NetAdapter -Name $adapter.Name -Confirm:$false -ErrorAction Stop;',
    '}',
    'if ($newComputerName -and $newComputerName -ne $env:COMPUTERNAME) {',
    '  Rename-Computer -NewName $newComputerName -Force -ErrorAction Stop;',
    '}',
    '[pscustomobject]@{ ok = $true; adapter = $adapter.Name; computerName = $newComputerName; mac = $newMac } | ConvertTo-Json -Depth 3'
  ].join(' ');
}

function stateFromRaw(raw: RawScanIdentityState | null, stored: StoredScanIdentityOriginals | null): ScanIdentityState {
  const currentComputerName = cleanString(raw?.computerName);
  const currentMac = normalizeMacAddress(cleanString(raw?.macAddress));
  const suggestedName = DEFAULT_SCAN_IDENTITY_NAME;
  const warnings = [
    'Changing computer name can require a reboot and can affect corporate/domain access until restored.',
    'Changing adapter MAC can disconnect Wi-Fi and can affect NAC/corporate access until restored.'
  ];

  return {
    schema: 'monitor.scan_identity.v1',
    ts_utc: new Date().toISOString(),
    supported: true,
    requires_admin: raw?.isAdmin !== true,
    interface_name: cleanString(raw?.interfaceName),
    adapter_name: cleanString(raw?.adapterName),
    current_computer_name: currentComputerName,
    current_mac_address: currentMac,
    active_mac_override: normalizeMacAddress(cleanString(raw?.activeMacOverride)),
    suggested_computer_name: suggestedName,
    suggested_mac_address: suggestedScanMac(suggestedName, currentMac),
    stored_original_computer_name: stored?.original_computer_name ?? null,
    stored_original_mac_address: stored?.original_mac_address ?? null,
    pending_reboot: Boolean(stored?.original_computer_name && currentComputerName && stored.original_computer_name !== currentComputerName),
    warnings,
    error: cleanString(raw?.error)
  };
}

function unsupportedState(error: string): ScanIdentityState {
  return {
    schema: 'monitor.scan_identity.v1',
    ts_utc: new Date().toISOString(),
    supported: false,
    requires_admin: false,
    interface_name: null,
    adapter_name: null,
    current_computer_name: null,
    current_mac_address: null,
    active_mac_override: null,
    suggested_computer_name: DEFAULT_SCAN_IDENTITY_NAME,
    suggested_mac_address: null,
    stored_original_computer_name: null,
    stored_original_mac_address: null,
    pending_reboot: false,
    warnings: [],
    error
  };
}

async function ensureStoredOriginals(
  state: ScanIdentityState,
  stateFile?: string | null
): Promise<StoredScanIdentityOriginals> {
  const existing = await readStoredOriginals(stateFile);
  if (existing?.original_computer_name || existing?.original_mac_address) {
    return existing;
  }

  const next: StoredScanIdentityOriginals = {
    schema: 'monitor.scan_identity_originals.v1',
    saved_at_utc: new Date().toISOString(),
    interface_name: state.interface_name,
    adapter_name: state.adapter_name,
    original_computer_name: state.current_computer_name,
    original_mac_address: state.current_mac_address,
    original_mac_override: state.active_mac_override
  };
  await writeStoredOriginals(next, stateFile);
  return next;
}

async function readStoredOriginals(stateFile?: string | null): Promise<StoredScanIdentityOriginals | null> {
  try {
    const raw = await readFile(stateFilePath(stateFile), 'utf8');
    const parsed = JSON.parse(raw) as Partial<StoredScanIdentityOriginals>;
    if (parsed.schema !== 'monitor.scan_identity_originals.v1') {
      return null;
    }
    return {
      schema: 'monitor.scan_identity_originals.v1',
      saved_at_utc: cleanString(parsed.saved_at_utc) ?? new Date().toISOString(),
      interface_name: cleanString(parsed.interface_name),
      adapter_name: cleanString(parsed.adapter_name),
      original_computer_name: normalizeComputerName(parsed.original_computer_name) ?? cleanString(parsed.original_computer_name),
      original_mac_address: normalizeMacAddress(parsed.original_mac_address),
      original_mac_override: normalizeMacAddress(parsed.original_mac_override)
    };
  } catch {
    return null;
  }
}

async function writeStoredOriginals(value: StoredScanIdentityOriginals, stateFile?: string | null): Promise<void> {
  const target = stateFilePath(stateFile);
  await mkdir(dirname(target), { recursive: true });
  await writeFile(target, `${JSON.stringify(value, null, 2)}\n`, 'utf8');
}

function changeResultFromState(
  action: 'apply' | 'restore',
  state: ScanIdentityState,
  changedComputerName: boolean,
  changedMacAddress: boolean,
  command: string,
  stdout: string,
  stderr: string,
  error: string | null
): ScanIdentityChangeResult {
  return {
    ...state,
    action,
    changed_computer_name: changedComputerName,
    changed_mac_address: changedMacAddress,
    command,
    stdout,
    stderr,
    error
  };
}

function parseRawState(stdout: string): RawScanIdentityState | null {
  const trimmed = stdout.trim();
  if (!trimmed) {
    return null;
  }

  return JSON.parse(trimmed) as RawScanIdentityState;
}

function stateFilePath(value?: string | null): string {
  return value ? resolve(value) : DEFAULT_STATE_FILE;
}

function suggestedScanMac(name: string, currentMac: string | null): string | null {
  const hash = createHash('sha256').update(`${name}|${currentMac ?? 'monitor'}`).digest();
  const bytes = [0x02, hash[0], hash[1], hash[2], hash[3], hash[4]];
  return bytes.map((byte) => byte.toString(16).padStart(2, '0')).join(':');
}

function normalizeComputerName(value: unknown): string | null {
  const cleaned = cleanString(value)?.toUpperCase() ?? '';
  if (!cleaned || cleaned.length > 15 || !/^[A-Z0-9](?:[A-Z0-9-]{0,13}[A-Z0-9])?$/.test(cleaned)) {
    return null;
  }
  if (/^\d+$/.test(cleaned)) {
    return null;
  }

  return cleaned;
}

function normalizeMacAddress(value: unknown, requireLocal = false): string | null {
  const raw = cleanString(value);
  if (!raw) {
    return null;
  }

  const hex = raw.replace(/[^a-fA-F0-9]/g, '').toLowerCase();
  if (hex.length !== 12 || hex === '000000000000') {
    return null;
  }
  const firstOctet = Number.parseInt(hex.slice(0, 2), 16);
  if (!Number.isFinite(firstOctet) || (firstOctet & 1) === 1) {
    return null;
  }
  if (requireLocal && (firstOctet & 2) !== 2) {
    return null;
  }

  return hex.match(/.{2}/g)?.join(':') ?? null;
}

function cleanString(value: unknown): string | null {
  if (typeof value !== 'string') {
    return null;
  }
  const trimmed = value.trim();
  return trimmed ? trimmed : null;
}

function psString(value: string | null): string {
  return value === null ? '$null' : `'${value.replace(/'/g, "''")}'`;
}
