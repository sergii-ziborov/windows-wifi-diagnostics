import { randomUUID } from 'node:crypto';
import { mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { dirname } from 'node:path';
import type {
  RadioChronBleAddressType,
  RadioChronBleFinding,
  RadioChronBleIdentityConfidence,
  RadioChronBleRiskKind
} from 'radiochron';
import type { DesktopBleScanResult } from './radiochronBle';

const BLE_HISTORY_SCHEMA_VERSION = 1 as const;
const BLE_HISTORY_MAX_AGE_MS = 30 * 24 * 60 * 60 * 1_000;
const BLE_HISTORY_MAX_SESSIONS = 512;
const BLE_HISTORY_MAX_POINTS_PER_SESSION = 512;

export interface DesktopBleHistoryPoint {
  identity_key: string;
  identity_confidence: RadioChronBleIdentityConfidence;
  protocol: string | null;
  local_name: string | null;
  address_type: RadioChronBleAddressType;
  rssi_dbm: number;
  payload_hash: string;
}

export interface DesktopBleHistoryFinding {
  kind: RadioChronBleRiskKind;
  severity: RadioChronBleFinding['severity'];
  identity_key: string | null;
  summary: string;
}

export interface DesktopBleHistorySession {
  scan_id: string;
  observed_at_ms: number;
  zone: string | null;
  elapsed_ms: number;
  adapter_count: number;
  advertisement_count: number;
  error_count: number;
  points: DesktopBleHistoryPoint[];
  findings: DesktopBleHistoryFinding[];
}

export interface DesktopBleHistoryArchive {
  schema_version: typeof BLE_HISTORY_SCHEMA_VERSION;
  generated_at_ms: number;
  storage_warning: string | null;
  retention: {
    max_age_days: 30;
    max_sessions: typeof BLE_HISTORY_MAX_SESSIONS;
  };
  sessions: DesktopBleHistorySession[];
}

export interface DesktopBleViewResult extends DesktopBleScanResult {
  analytics_history: DesktopBleHistoryArchive;
}

export function emptyBleHistory(nowMs = Date.now(), storageWarning: string | null = null): DesktopBleHistoryArchive {
  return {
    schema_version: BLE_HISTORY_SCHEMA_VERSION,
    generated_at_ms: nowMs,
    storage_warning: storageWarning,
    retention: {
      max_age_days: 30,
      max_sessions: BLE_HISTORY_MAX_SESSIONS
    },
    sessions: []
  };
}

export async function readBleHistory(filePath: string, nowMs = Date.now()): Promise<DesktopBleHistoryArchive> {
  try {
    const parsed = JSON.parse(await readFile(filePath, 'utf8')) as unknown;
    return normalizeArchive(parsed, nowMs);
  } catch (error: unknown) {
    if (isMissingFile(error)) return emptyBleHistory(nowMs);
    return emptyBleHistory(nowMs, `Stored Bluetooth history could not be read: ${errorMessage(error)}`);
  }
}

export async function appendBleHistory(
  filePath: string,
  result: DesktopBleScanResult,
  zone: string | null
): Promise<DesktopBleHistoryArchive> {
  const nowMs = result.scanned_at_ms;
  const current = await readBleHistory(filePath, nowMs);
  const cutoff = nowMs - BLE_HISTORY_MAX_AGE_MS;
  const session = createSession(result, zone);
  const sessions = [...current.sessions.filter((item) => item.observed_at_ms >= cutoff), session]
    .sort((left, right) => left.observed_at_ms - right.observed_at_ms)
    .slice(-BLE_HISTORY_MAX_SESSIONS);
  const archive: DesktopBleHistoryArchive = {
    ...emptyBleHistory(nowMs),
    sessions
  };

  try {
    await mkdir(dirname(filePath), { recursive: true });
    await writeFile(filePath, `${JSON.stringify(archive, null, 2)}\n`, 'utf8');
    return archive;
  } catch (error: unknown) {
    return {
      ...archive,
      storage_warning: `Bluetooth scan completed, but history could not be saved: ${errorMessage(error)}`
    };
  }
}

export async function clearBleHistory(filePath: string): Promise<void> {
  await rm(filePath, { force: true });
}

function createSession(result: DesktopBleScanResult, zone: string | null): DesktopBleHistorySession {
  const points = result.observations
    .slice(0, BLE_HISTORY_MAX_POINTS_PER_SESSION)
    .map((observation, index): DesktopBleHistoryPoint | null => {
      const advertisement = result.scan.advertisements[index];
      if (!advertisement) return null;
      return {
        identity_key: observation.identity.key,
        identity_confidence: observation.identity.confidence,
        protocol: observation.identity.protocol,
        local_name: advertisement.local_name?.slice(0, 160) ?? null,
        address_type: advertisement.address_type,
        rssi_dbm: advertisement.rssi_dbm,
        payload_hash: observation.payload_hash
      };
    })
    .filter((point): point is DesktopBleHistoryPoint => point !== null);

  return {
    scan_id: randomUUID(),
    observed_at_ms: result.scanned_at_ms,
    zone: normalizedOptionalText(zone, 120),
    elapsed_ms: result.scan.elapsed_ms,
    adapter_count: result.scan.adapter_count,
    advertisement_count: result.scan.advertisements.length,
    error_count: result.scan.errors.length,
    points,
    findings: result.findings.map((finding) => ({
      kind: finding.kind,
      severity: finding.severity,
      identity_key: finding.identity_key,
      summary: finding.summary.slice(0, 500)
    }))
  };
}

function normalizeArchive(value: unknown, nowMs: number): DesktopBleHistoryArchive {
  if (!isRecord(value) || value.schema_version !== BLE_HISTORY_SCHEMA_VERSION || !Array.isArray(value.sessions)) {
    return emptyBleHistory(nowMs, 'Stored Bluetooth history uses an unsupported or invalid schema.');
  }

  const cutoff = nowMs - BLE_HISTORY_MAX_AGE_MS;
  const sessions = value.sessions
    .map(normalizeSession)
    .filter((session): session is DesktopBleHistorySession => session !== null && session.observed_at_ms >= cutoff)
    .sort((left, right) => left.observed_at_ms - right.observed_at_ms)
    .slice(-BLE_HISTORY_MAX_SESSIONS);
  return {
    ...emptyBleHistory(nowMs),
    sessions
  };
}

function normalizeSession(value: unknown): DesktopBleHistorySession | null {
  if (!isRecord(value) || typeof value.scan_id !== 'string' || !finiteNumber(value.observed_at_ms)) return null;
  if (!Array.isArray(value.points) || !Array.isArray(value.findings)) return null;
  const points = value.points.map(normalizePoint).filter((point): point is DesktopBleHistoryPoint => point !== null);
  const findings = value.findings
    .map(normalizeFinding)
    .filter((finding): finding is DesktopBleHistoryFinding => finding !== null);
  return {
    scan_id: value.scan_id.slice(0, 160),
    observed_at_ms: value.observed_at_ms,
    zone: normalizedOptionalText(value.zone, 120),
    elapsed_ms: finiteNumber(value.elapsed_ms) ? value.elapsed_ms : 0,
    adapter_count: finiteNumber(value.adapter_count) ? value.adapter_count : 0,
    advertisement_count: finiteNumber(value.advertisement_count) ? value.advertisement_count : points.length,
    error_count: finiteNumber(value.error_count) ? value.error_count : 0,
    points: points.slice(0, BLE_HISTORY_MAX_POINTS_PER_SESSION),
    findings
  };
}

function normalizePoint(value: unknown): DesktopBleHistoryPoint | null {
  if (!isRecord(value) || typeof value.identity_key !== 'string' || !finiteNumber(value.rssi_dbm)) return null;
  if (!isIdentityConfidence(value.identity_confidence) || !isAddressType(value.address_type)) return null;
  return {
    identity_key: value.identity_key.slice(0, 160),
    identity_confidence: value.identity_confidence,
    protocol: normalizedOptionalText(value.protocol, 80),
    local_name: normalizedOptionalText(value.local_name, 160),
    address_type: value.address_type,
    rssi_dbm: value.rssi_dbm,
    payload_hash: typeof value.payload_hash === 'string' ? value.payload_hash.slice(0, 160) : ''
  };
}

function normalizeFinding(value: unknown): DesktopBleHistoryFinding | null {
  if (!isRecord(value) || !isRiskKind(value.kind) || !isSeverity(value.severity)) return null;
  return {
    kind: value.kind,
    severity: value.severity,
    identity_key: normalizedOptionalText(value.identity_key, 160),
    summary: typeof value.summary === 'string' ? value.summary.slice(0, 500) : ''
  };
}

function normalizedOptionalText(value: unknown, maxLength: number): string | null {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  return trimmed ? trimmed.slice(0, maxLength) : null;
}

function finiteNumber(value: unknown): value is number {
  return typeof value === 'number' && Number.isFinite(value);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

function isMissingFile(error: unknown): boolean {
  return isRecord(error) && error.code === 'ENOENT';
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function isIdentityConfidence(value: unknown): value is RadioChronBleIdentityConfidence {
  return ['protocol', 'caller_provided', 'static_address', 'ephemeral_address'].includes(String(value));
}

function isAddressType(value: unknown): value is RadioChronBleAddressType {
  return ['public', 'random_static', 'resolvable_private', 'non_resolvable_private', 'unknown'].includes(String(value));
}

function isRiskKind(value: unknown): value is RadioChronBleRiskKind {
  return ['persistent_unknown', 'co_travel', 'disappeared', 'possible_clone', 'beacon_flood'].includes(String(value));
}

function isSeverity(value: unknown): value is RadioChronBleFinding['severity'] {
  return ['info', 'warning', 'high'].includes(String(value));
}
