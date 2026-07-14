import { createHash, randomUUID } from 'node:crypto';
import { mkdir } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { DEFAULT_RUN_DATABASE_FILE } from './runStore';
import { assessNetworkVulnerabilityIntel } from './vulnerabilityIntel';
import type {
  DeviceInventoryAlert,
  DeviceHistoryRecord,
  DeviceHistoryResult,
  DeviceHistoryHourBucket,
  DeviceInventoryPersistenceResult,
  DeviceMetricRecord,
  DeviceVulnerabilityLookupResult,
  ScanLocationInput,
  ScanLocationRecord,
  ScanLocationsResult,
  VulnerabilityScanPlan,
  VulnerabilityScanPlanCheck,
  VulnerabilityIntelAssessment,
  VulnerabilityIntelSignal,
  VulnerabilityLookupMode,
  WindowsWifiNetwork
} from './types';

interface InventoryRow {
  id: number;
  bssid: string;
  ssid: string | null;
  ssid_norm: string | null;
  oui: string | null;
  vendor: string | null;
  device_hint: string | null;
  mac_scope: string | null;
  identity_fingerprint: string;
  authentication: string | null;
  encryption: string | null;
  radio_type: string | null;
  first_seen_utc: string;
  last_seen_utc: string;
  seen_count: number;
  latest_signal_percent?: number | null;
  latest_channel?: number | null;
  latest_payload_json?: string;
}

interface ObservationRow {
  bssid: string | null;
  ts_utc: string;
  signal_percent: number | null;
  channel: number | null;
  payload_json: string;
}

interface MetricRow {
  bssid: string;
  location_id: number | null;
  location_key: string;
  first_seen_utc: string;
  last_seen_utc: string;
  seen_count: number;
  signal_min_percent: number | null;
  signal_max_percent: number | null;
  signal_avg_percent: number | null;
  signal_latest_percent: number | null;
  latest_channel: number | null;
  channels_json: string;
  bands_json: string;
  authentication: string | null;
  encryption: string | null;
  last_payload_hash: string | null;
  ssid?: string | null;
  latest_payload_json?: string | null;
}

interface ScanLocationRow {
  id: number;
  location_key: string;
  label: string | null;
  latitude: number;
  longitude: number;
  source: 'browser' | 'manual';
  first_seen_utc: string;
  last_seen_utc: string;
  scan_count: number;
}

interface DeviceInventoryPersistOptions {
  databaseFile?: string | null;
  location?: ScanLocationInput | null;
}

const EXPOSURE_ORDER: Record<VulnerabilityIntelAssessment['exposure_level'], number> = {
  none: 0,
  watch: 1,
  review: 2,
  priority: 3
};

const CONFIDENCE_ORDER: Record<VulnerabilityIntelAssessment['confidence'], number> = {
  low: 0,
  medium: 1,
  high: 2
};

const SCAN_LOCATION_RADIUS_METERS = 50;
const UNLOCATED_LOCATION_KEY = 'unlocated';
const DEVICE_OBSERVATION_CLEANUP_KEY = 'device_observations_compacted_v1';

const PASSIVE_VULNERABILITY_SCAN_CHECK_IDS = new Set([
  'inventory_correlation',
  'radio_security_metadata',
  'vendor_advisory_context',
  'identity_drift_review',
  'pmf_wpa3_capability_review',
  'wps_metadata_review'
]);

const VULNERABILITY_SCAN_CHECKS: Array<Omit<VulnerabilityScanPlanCheck, 'selected'>> = [
  {
    id: 'inventory_correlation',
    label: 'Saved inventory correlation',
    description: 'Compare this AP against saved BSSID, SSID, vendor, security, and history fingerprints.',
    available: true,
    impact: 'local_only',
    network_effect: 'No network traffic; reads local SQLite inventory.',
    blocked_reason: null
  },
  {
    id: 'radio_security_metadata',
    label: 'Radio and security metadata',
    description: 'Use Windows scan metadata, advertised authentication, cipher, band, channel, rates, and native BSS details.',
    available: true,
    impact: 'none',
    network_effect: 'No new traffic beyond normal Windows Wi-Fi telemetry already collected.',
    blocked_reason: null
  },
  {
    id: 'vendor_advisory_context',
    label: 'Vendor advisory context',
    description: 'Attach local vendor/OUI/device-role evidence and advisory lookup references for later CVE/CPE work.',
    available: true,
    impact: 'local_only',
    network_effect: 'No packets sent to the AP; saves local advisory context.',
    blocked_reason: null
  },
  {
    id: 'identity_drift_review',
    label: 'BSSID identity drift review',
    description: 'Flag same-looking AP identities that appear with a changed BSSID/MAC fingerprint.',
    available: true,
    impact: 'local_only',
    network_effect: 'No network traffic; compares saved observations.',
    blocked_reason: null
  },
  {
    id: 'pmf_wpa3_capability_review',
    label: 'PMF / WPA3 upgrade gap review',
    description: 'Record whether metadata suggests WPA2-only operation, transition risk, or missing WPA3/PMF evidence.',
    available: true,
    impact: 'none',
    network_effect: 'No traffic; uses advertised security metadata and native information elements when available.',
    blocked_reason: null
  },
  {
    id: 'wps_metadata_review',
    label: 'WPS exposure metadata review',
    description: 'Save whether WPS-like metadata needs manual router-side confirmation.',
    available: true,
    impact: 'none',
    network_effect: 'No WPS exchange; records that WPS must be checked from router configuration or authorized tooling.',
    blocked_reason: null
  }
];

export async function persistNetworkInventory(
  networks: WindowsWifiNetwork[],
  optionsOrDatabaseFile?: string | null | DeviceInventoryPersistOptions
): Promise<DeviceInventoryPersistenceResult> {
  const options = normalizePersistOptions(optionsOrDatabaseFile);
  const store = await openDeviceInventoryStore(options.databaseFile);
  try {
    return store.persistNetworks(networks, options.location ?? null);
  } finally {
    store.close();
  }
}

export async function applyInventoryThreatSignals(
  networks: WindowsWifiNetwork[],
  databaseFile?: string | null
): Promise<WindowsWifiNetwork[]> {
  if (networks.length === 0) {
    return networks;
  }

  const store = await openDeviceInventoryStore(databaseFile);
  try {
    return networks.map((network) => mergeInventoryAlerts(network, store.findIdentityAlerts(network)));
  } finally {
    store.close();
  }
}

export async function runDeviceVulnerabilityLookup(options: {
  mode: VulnerabilityLookupMode;
  network: WindowsWifiNetwork;
  selectedCheckIds?: string[];
  operatorNote?: string | null;
  databaseFile?: string | null;
}): Promise<DeviceVulnerabilityLookupResult> {
  const scanId = `vuln-${Date.now().toString(36)}-${randomUUID()}`;
  const scanPlan = buildVulnerabilityScanPlan(options.mode, {
    selectedCheckIds: options.selectedCheckIds,
    operatorNote: options.operatorNote
  });
  const store = await openDeviceInventoryStore(options.databaseFile);
  try {
    const alerts = store.findIdentityAlerts(options.network);
    const networkWithAlerts = mergeInventoryAlerts(options.network, alerts);
    const vulnerabilityIntel = enrichLookupIntel(
      networkWithAlerts.vulnerability_intel ?? assessNetworkVulnerabilityIntel(networkWithAlerts),
      options.mode,
      networkWithAlerts,
      alerts,
      scanPlan
    );
    store.persistNetworks([{ ...networkWithAlerts, vulnerability_intel: vulnerabilityIntel }]);
    store.saveVulnerabilityScan({
      scanId,
      mode: options.mode,
      network: options.network,
      vulnerabilityIntel,
      alerts,
      scanPlan
    });

    return {
      mode: options.mode,
      saved: true,
      scan_id: scanId,
      status: 'saved',
      summary: vulnerabilityIntel.summary,
      scan_plan: scanPlan,
      vulnerability_intel: vulnerabilityIntel,
      alerts,
      database_file: store.databaseFile,
      error: null
    };
  } catch (error) {
    return {
      mode: options.mode,
      saved: false,
      scan_id: scanId,
      status: 'failed',
      summary: 'Vulnerability lookup failed.',
      scan_plan: scanPlan,
      vulnerability_intel: null,
      alerts: [],
      database_file: store.databaseFile,
      error: error instanceof Error ? error.message : String(error)
    };
  } finally {
    store.close();
  }
}

export async function listDeviceHistory(options: {
  databaseFile?: string | null;
  newWindowHours?: number;
} = {}): Promise<DeviceHistoryResult> {
  const store = await openDeviceInventoryStore(options.databaseFile);
  try {
    return store.listDeviceHistory(options.newWindowHours);
  } finally {
    store.close();
  }
}

export async function listScanLocations(options: {
  databaseFile?: string | null;
} = {}): Promise<ScanLocationsResult> {
  const store = await openDeviceInventoryStore(options.databaseFile);
  try {
    return store.listScanLocations();
  } finally {
    store.close();
  }
}

class DeviceInventoryStore {
  private readonly db: DatabaseSync;

  constructor(readonly databaseFile: string) {
    this.db = new DatabaseSync(databaseFile);
    this.db.exec(`
      PRAGMA busy_timeout = 5000;
      PRAGMA journal_mode = WAL;
      PRAGMA synchronous = NORMAL;

      CREATE TABLE IF NOT EXISTS device_inventory (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        bssid TEXT NOT NULL UNIQUE,
        ssid TEXT,
        ssid_norm TEXT,
        oui TEXT,
        vendor TEXT,
        vendor_key TEXT,
        device_hint TEXT,
        mac_scope TEXT,
        identity_fingerprint TEXT NOT NULL,
        authentication TEXT,
        encryption TEXT,
        radio_type TEXT,
        first_seen_utc TEXT NOT NULL,
        last_seen_utc TEXT NOT NULL,
        seen_count INTEGER NOT NULL DEFAULT 0,
        latest_signal_percent INTEGER,
        latest_channel INTEGER,
        latest_payload_json TEXT NOT NULL
      );

      CREATE INDEX IF NOT EXISTS idx_device_inventory_fingerprint
        ON device_inventory(identity_fingerprint);

      CREATE INDEX IF NOT EXISTS idx_device_inventory_vendor
        ON device_inventory(vendor_key);

      CREATE TABLE IF NOT EXISTS device_observations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        inventory_id INTEGER REFERENCES device_inventory(id) ON DELETE SET NULL,
        bssid TEXT,
        ssid TEXT,
        run_id TEXT,
        ts_utc TEXT NOT NULL,
        signal_percent INTEGER,
        channel INTEGER,
        payload_json TEXT NOT NULL
      );

      CREATE INDEX IF NOT EXISTS idx_device_observations_bssid_time
        ON device_observations(bssid, ts_utc);

      CREATE TABLE IF NOT EXISTS scan_locations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        location_key TEXT NOT NULL UNIQUE,
        label TEXT,
        latitude REAL NOT NULL,
        longitude REAL NOT NULL,
        source TEXT NOT NULL,
        first_seen_utc TEXT NOT NULL,
        last_seen_utc TEXT NOT NULL,
        scan_count INTEGER NOT NULL DEFAULT 0
      );

      CREATE INDEX IF NOT EXISTS idx_scan_locations_last_seen
        ON scan_locations(last_seen_utc);

      CREATE TABLE IF NOT EXISTS device_metrics (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        bssid TEXT NOT NULL,
        location_id INTEGER REFERENCES scan_locations(id) ON DELETE SET NULL,
        location_key TEXT NOT NULL DEFAULT 'unlocated',
        first_seen_utc TEXT NOT NULL,
        last_seen_utc TEXT NOT NULL,
        seen_count INTEGER NOT NULL DEFAULT 0,
        signal_min_percent INTEGER,
        signal_max_percent INTEGER,
        signal_avg_percent REAL,
        signal_latest_percent INTEGER,
        latest_channel INTEGER,
        channels_json TEXT NOT NULL DEFAULT '[]',
        bands_json TEXT NOT NULL DEFAULT '[]',
        authentication TEXT,
        encryption TEXT,
        last_payload_hash TEXT,
        UNIQUE(bssid, location_key)
      );

      CREATE INDEX IF NOT EXISTS idx_device_metrics_location
        ON device_metrics(location_key, last_seen_utc);

      CREATE INDEX IF NOT EXISTS idx_device_metrics_bssid
        ON device_metrics(bssid);

      CREATE TABLE IF NOT EXISTS vendors (
        vendor_key TEXT PRIMARY KEY,
        vendor TEXT NOT NULL,
        first_seen_utc TEXT NOT NULL,
        last_seen_utc TEXT NOT NULL,
        device_count INTEGER NOT NULL DEFAULT 0,
        oui_count INTEGER NOT NULL DEFAULT 0
      );

      CREATE TABLE IF NOT EXISTS vendor_ouis (
        vendor_key TEXT NOT NULL,
        oui TEXT NOT NULL,
        first_seen_utc TEXT NOT NULL,
        last_seen_utc TEXT NOT NULL,
        seen_count INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (vendor_key, oui)
      );

      CREATE TABLE IF NOT EXISTS device_identity_alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        alert_type TEXT NOT NULL,
        severity TEXT NOT NULL,
        identity_fingerprint TEXT NOT NULL,
        ssid TEXT,
        current_bssid TEXT,
        previous_bssid TEXT,
        evidence_json TEXT NOT NULL,
        created_at_utc TEXT NOT NULL,
        UNIQUE(alert_type, identity_fingerprint, current_bssid, previous_bssid)
      );

      CREATE TABLE IF NOT EXISTS vulnerability_scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id TEXT NOT NULL UNIQUE,
        mode TEXT NOT NULL,
        bssid TEXT,
        ssid TEXT,
        status TEXT NOT NULL,
        summary TEXT NOT NULL,
        exposure_level TEXT,
        confidence TEXT,
        signals_json TEXT NOT NULL,
        alerts_json TEXT NOT NULL,
        payload_json TEXT NOT NULL,
        created_at_utc TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS maintenance_state (
        key TEXT PRIMARY KEY,
        completed_at_utc TEXT NOT NULL,
        detail TEXT
      );
    `);
    this.runStartupMaintenance();
  }

  persistNetworks(networks: WindowsWifiNetwork[], locationInput: ScanLocationInput | null = null): DeviceInventoryPersistenceResult {
    let storedDevices = 0;
    let storedObservations = 0;
    let storedVendors = 0;
    const alerts: DeviceInventoryAlert[] = [];
    const scanLocation = locationInput ? this.resolveScanLocation(locationInput) : null;

    for (const network of networks) {
      const bssid = normalizeMacAddress(network.bssid);
      if (!bssid) {
        continue;
      }

      const networkAlerts = this.findIdentityAlerts(network);
      for (const alert of networkAlerts) {
        this.saveIdentityAlert(alert, identityFingerprint(network));
      }
      alerts.push(...networkAlerts);
      this.upsertDevice(network, bssid);
      storedDevices += 1;
      storedObservations += this.upsertDeviceMetric(network, bssid, scanLocation);
      if (this.upsertVendor(network)) {
        storedVendors += 1;
      }
    }

    return {
      stored_devices: storedDevices,
      stored_observations: storedObservations,
      stored_vendors: storedVendors,
      scan_location: scanLocation,
      alerts
    };
  }

  findIdentityAlerts(network: WindowsWifiNetwork): DeviceInventoryAlert[] {
    const bssid = normalizeMacAddress(network.bssid);
    const fingerprint = identityFingerprint(network);
    if (!bssid || !fingerprint) {
      return [];
    }

    const rows = this.db.prepare(`
      SELECT
        id,
        bssid,
        ssid,
        ssid_norm,
        oui,
        vendor,
        device_hint,
        mac_scope,
        identity_fingerprint,
        authentication,
        encryption,
        radio_type,
        first_seen_utc,
        last_seen_utc,
        seen_count
      FROM device_inventory
      WHERE identity_fingerprint = ?
        AND bssid <> ?
      ORDER BY datetime(last_seen_utc) DESC
      LIMIT 5
    `).all(fingerprint, bssid) as unknown as InventoryRow[];

    return rows
      .filter((row) => !isExpectedMeshPeerIdentity(network, row))
      .map((row) => ({
        alert_type: 'identity_mac_changed',
        severity: row.vendor && row.device_hint ? 'high' : 'medium',
        summary:
          'A previously saved AP has the same SSID/vendor/security fingerprint but a different BSSID. This can be normal mesh hardware, replacement hardware, randomized/local BSSID behavior, or a lookalike AP that needs review.',
        ssid: network.ssid ?? row.ssid,
        current_bssid: bssid,
        previous_bssid: row.bssid,
        evidence: [
          `ssid=${network.ssid ?? row.ssid ?? 'unknown'}`,
          `vendor=${network.mac_enrichment?.vendor ?? row.vendor ?? 'unknown'}`,
          `device_hint=${network.mac_enrichment?.device_hint ?? row.device_hint ?? 'unknown'}`,
          `authentication=${network.authentication ?? row.authentication ?? 'unknown'}`,
          `encryption=${network.encryption ?? row.encryption ?? 'unknown'}`,
          `previous_last_seen=${row.last_seen_utc}`
        ],
        created_at_utc: new Date().toISOString()
      }));
  }

  saveVulnerabilityScan(input: {
    scanId: string;
    mode: VulnerabilityLookupMode;
    network: WindowsWifiNetwork;
    vulnerabilityIntel: VulnerabilityIntelAssessment;
    alerts: DeviceInventoryAlert[];
    scanPlan: VulnerabilityScanPlan;
  }): void {
    const now = new Date().toISOString();
    this.db.prepare(`
      INSERT INTO vulnerability_scans (
        scan_id,
        mode,
        bssid,
        ssid,
        status,
        summary,
        exposure_level,
        confidence,
        signals_json,
        alerts_json,
        payload_json,
        created_at_utc
      )
      VALUES (?, ?, ?, ?, 'saved', ?, ?, ?, ?, ?, ?, ?)
    `).run(
      input.scanId,
      input.mode,
      normalizeMacAddress(input.network.bssid),
      input.network.ssid,
      input.vulnerabilityIntel.summary,
      input.vulnerabilityIntel.exposure_level,
      input.vulnerabilityIntel.confidence,
      JSON.stringify(input.vulnerabilityIntel.signals),
      JSON.stringify(input.alerts),
      JSON.stringify({
        network: input.network,
        scan_plan: input.scanPlan,
        vulnerability_intel: input.vulnerabilityIntel,
        alerts: input.alerts
      }),
      now
    );
  }

  listDeviceHistory(newWindowHours = 24): DeviceHistoryResult {
    const boundedNewWindowHours = Math.min(24 * 30, Math.max(1, Math.trunc(newWindowHours)));
    const rows = this.db.prepare(`
      SELECT
        id,
        bssid,
        ssid,
        ssid_norm,
        oui,
        vendor,
        device_hint,
        mac_scope,
        identity_fingerprint,
        authentication,
        encryption,
        radio_type,
        first_seen_utc,
        last_seen_utc,
        seen_count,
        latest_signal_percent,
        latest_channel,
        latest_payload_json
      FROM device_inventory
      ORDER BY datetime(last_seen_utc) DESC, bssid ASC
    `).all() as unknown as InventoryRow[];
    const metrics = this.db.prepare(`
      SELECT
        m.bssid,
        m.location_id,
        m.location_key,
        m.first_seen_utc,
        m.last_seen_utc,
        m.seen_count,
        m.signal_min_percent,
        m.signal_max_percent,
        m.signal_avg_percent,
        m.signal_latest_percent,
        m.latest_channel,
        m.channels_json,
        m.bands_json,
        m.authentication,
        m.encryption,
        m.last_payload_hash,
        i.ssid,
        i.latest_payload_json
      FROM device_metrics m
      LEFT JOIN device_inventory i ON i.bssid = m.bssid
      ORDER BY datetime(m.last_seen_utc) ASC, m.id ASC
    `).all() as unknown as MetricRow[];
    const metricsByBssid = new Map<string, MetricRow[]>();
    for (const metric of metrics) {
      const bssid = normalizeMacAddress(metric.bssid);
      if (!bssid) {
        continue;
      }
      metricsByBssid.set(bssid, [...(metricsByBssid.get(bssid) ?? []), metric]);
    }
    const nowMs = Date.now();
    const newWindowMs = boundedNewWindowHours * 60 * 60 * 1000;
    const records = rows.map((row) => historyRecordFromRow(
      row,
      metricsByBssid.get(row.bssid) ?? [],
      nowMs,
      newWindowMs
    ));

    return {
      database_file: this.databaseFile,
      generated_at_utc: new Date(nowMs).toISOString(),
      new_window_hours: boundedNewWindowHours,
      total_devices: records.length,
      records
    };
  }

  listScanLocations(): ScanLocationsResult {
    const locations = (this.db.prepare(`
      SELECT id, location_key, label, latitude, longitude, source, first_seen_utc, last_seen_utc, scan_count
      FROM scan_locations
      ORDER BY datetime(last_seen_utc) DESC, id DESC
    `).all() as unknown as ScanLocationRow[]).map(scanLocationFromRow);
    const metrics = (this.db.prepare(`
      SELECT
        m.bssid,
        m.location_id,
        m.location_key,
        m.first_seen_utc,
        m.last_seen_utc,
        m.seen_count,
        m.signal_min_percent,
        m.signal_max_percent,
        m.signal_avg_percent,
        m.signal_latest_percent,
        m.latest_channel,
        m.channels_json,
        m.bands_json,
        m.authentication,
        m.encryption,
        m.last_payload_hash,
        i.ssid,
        i.latest_payload_json
      FROM device_metrics m
      LEFT JOIN device_inventory i ON i.bssid = m.bssid
      ORDER BY datetime(m.last_seen_utc) DESC, m.bssid ASC
    `).all() as unknown as MetricRow[]).map(metricRecordFromRow);

    return {
      database_file: this.databaseFile,
      generated_at_utc: new Date().toISOString(),
      locations,
      metrics
    };
  }

  private resolveScanLocation(input: ScanLocationInput): ScanLocationRecord {
    const latitude = clampCoordinate(input.latitude, -90, 90);
    const longitude = clampCoordinate(input.longitude, -180, 180);
    const source = input.source === 'browser' ? 'browser' : 'manual';
    const label = cleanOperatorText(input.label, 120);
    const now = new Date().toISOString();
    const rows = this.db.prepare(`
      SELECT id, location_key, label, latitude, longitude, source, first_seen_utc, last_seen_utc, scan_count
      FROM scan_locations
    `).all() as unknown as ScanLocationRow[];
    const nearest = rows
      .map((row) => ({ row, distanceMeters: haversineMeters(latitude, longitude, row.latitude, row.longitude) }))
      .sort((left, right) => left.distanceMeters - right.distanceMeters)[0] ?? null;

    if (nearest && nearest.distanceMeters <= SCAN_LOCATION_RADIUS_METERS) {
      this.db.prepare(`
        UPDATE scan_locations
        SET
          label = COALESCE(?, label),
          source = ?,
          latitude = ?,
          longitude = ?,
          last_seen_utc = ?,
          scan_count = scan_count + 1
        WHERE id = ?
      `).run(label, source, latitude, longitude, now, nearest.row.id);

      const row = this.db.prepare(`
        SELECT id, location_key, label, latitude, longitude, source, first_seen_utc, last_seen_utc, scan_count
        FROM scan_locations
        WHERE id = ?
      `).get(nearest.row.id) as unknown as ScanLocationRow;
      return scanLocationFromRow(row);
    }

    const locationKey = `loc-${Math.round(latitude * 1_000_000)}-${Math.round(longitude * 1_000_000)}-${Date.now().toString(36)}`;
    this.db.prepare(`
      INSERT INTO scan_locations (
        location_key,
        label,
        latitude,
        longitude,
        source,
        first_seen_utc,
        last_seen_utc,
        scan_count
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, 1)
    `).run(locationKey, label, latitude, longitude, source, now, now);

    const row = this.db.prepare(`
      SELECT id, location_key, label, latitude, longitude, source, first_seen_utc, last_seen_utc, scan_count
      FROM scan_locations
      WHERE location_key = ?
    `).get(locationKey) as unknown as ScanLocationRow;
    return scanLocationFromRow(row);
  }

  private runStartupMaintenance(): void {
    const completed = this.db.prepare('SELECT key FROM maintenance_state WHERE key = ?').get(DEVICE_OBSERVATION_CLEANUP_KEY);
    if (completed) {
      return;
    }

    const observations = this.db.prepare(`
      SELECT bssid, ts_utc, signal_percent, channel, payload_json
      FROM device_observations
      ORDER BY datetime(ts_utc) ASC, id ASC
    `).all() as unknown as ObservationRow[];
    let compacted = 0;

    for (const observation of observations) {
      const network = parseNetworkPayload(observation.payload_json);
      const bssid = normalizeMacAddress(network?.bssid ?? observation.bssid);
      if (!network || !bssid) {
        continue;
      }

      this.upsertDeviceMetric(
        {
          ...network,
          ts_utc: network.ts_utc || observation.ts_utc,
          signal_percent: network.signal_percent ?? observation.signal_percent,
          channel: network.channel ?? observation.channel
        },
        bssid,
        null
      );
      compacted += 1;
    }

    this.db.prepare('DELETE FROM device_observations').run();
    this.db.prepare(`
      INSERT INTO maintenance_state (key, completed_at_utc, detail)
      VALUES (?, ?, ?)
      ON CONFLICT(key) DO UPDATE SET
        completed_at_utc = excluded.completed_at_utc,
        detail = excluded.detail
    `).run(DEVICE_OBSERVATION_CLEANUP_KEY, new Date().toISOString(), `compacted=${compacted};deleted=${observations.length}`);
  }

  close(): void {
    this.db.close();
  }

  private upsertDevice(network: WindowsWifiNetwork, bssid: string): number {
    const now = new Date().toISOString();
    const fingerprint = identityFingerprint(network);
    this.db.prepare(`
      INSERT INTO device_inventory (
        bssid,
        ssid,
        ssid_norm,
        oui,
        vendor,
        vendor_key,
        device_hint,
        mac_scope,
        identity_fingerprint,
        authentication,
        encryption,
        radio_type,
        first_seen_utc,
        last_seen_utc,
        seen_count,
        latest_signal_percent,
        latest_channel,
        latest_payload_json
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?)
      ON CONFLICT(bssid) DO UPDATE SET
        ssid = excluded.ssid,
        ssid_norm = excluded.ssid_norm,
        oui = excluded.oui,
        vendor = excluded.vendor,
        vendor_key = excluded.vendor_key,
        device_hint = excluded.device_hint,
        mac_scope = excluded.mac_scope,
        identity_fingerprint = excluded.identity_fingerprint,
        authentication = excluded.authentication,
        encryption = excluded.encryption,
        radio_type = excluded.radio_type,
        last_seen_utc = excluded.last_seen_utc,
        seen_count = device_inventory.seen_count + 1,
        latest_signal_percent = excluded.latest_signal_percent,
        latest_channel = excluded.latest_channel,
        latest_payload_json = excluded.latest_payload_json
    `).run(
      bssid,
      network.ssid,
      normalizeSsid(network.ssid),
      normalizeOui(network.mac_enrichment?.oui ?? bssid.split(':').slice(0, 3).join(':')),
      network.mac_enrichment?.vendor ?? null,
      normalizeText(network.mac_enrichment?.vendor ?? null),
      network.mac_enrichment?.device_hint ?? null,
      network.mac_enrichment?.address_scope ?? null,
      fingerprint,
      network.authentication,
      network.encryption,
      network.radio_type,
      network.ts_utc ?? now,
      now,
      network.signal_percent,
      network.channel,
      JSON.stringify(network)
    );

    const row = this.db.prepare('SELECT id FROM device_inventory WHERE bssid = ?').get(bssid) as { id: number };
    return row.id;
  }

  private upsertDeviceMetric(network: WindowsWifiNetwork, bssid: string, location: ScanLocationRecord | null): number {
    const locationId = location?.id ?? null;
    const locationKey = location?.location_key ?? UNLOCATED_LOCATION_KEY;
    const tsUtc = network.ts_utc ?? new Date().toISOString();
    const signal = finiteIntegerOrNull(network.signal_percent);
    const existing = this.db.prepare(`
      SELECT
        bssid,
        location_id,
        location_key,
        first_seen_utc,
        last_seen_utc,
        seen_count,
        signal_min_percent,
        signal_max_percent,
        signal_avg_percent,
        signal_latest_percent,
        latest_channel,
        channels_json,
        bands_json,
        authentication,
        encryption,
        last_payload_hash
      FROM device_metrics
      WHERE bssid = ? AND location_key = ?
    `).get(bssid, locationKey) as MetricRow | undefined;
    const seenCount = Math.max(0, existing?.seen_count ?? 0) + 1;
    const signalMin = signal === null ? existing?.signal_min_percent ?? null : Math.min(existing?.signal_min_percent ?? signal, signal);
    const signalMax = signal === null ? existing?.signal_max_percent ?? null : Math.max(existing?.signal_max_percent ?? signal, signal);
    const previousAvg = existing?.signal_avg_percent ?? null;
    const signalAvg =
      signal === null
        ? previousAvg
        : previousAvg === null
          ? signal
          : Math.round((((previousAvg * Math.max(0, seenCount - 1)) + signal) / seenCount) * 10) / 10;
    const channels = sortedNumberUnion(parseNumberArray(existing?.channels_json), network.channel);
    const bands = sortedStringUnion(parseStringArray(existing?.bands_json), network.band);
    const payloadHash = hashNetworkPayload(network);

    this.db.prepare(`
      INSERT INTO device_metrics (
        bssid,
        location_id,
        location_key,
        first_seen_utc,
        last_seen_utc,
        seen_count,
        signal_min_percent,
        signal_max_percent,
        signal_avg_percent,
        signal_latest_percent,
        latest_channel,
        channels_json,
        bands_json,
        authentication,
        encryption,
        last_payload_hash
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(bssid, location_key) DO UPDATE SET
        location_id = excluded.location_id,
        last_seen_utc = excluded.last_seen_utc,
        seen_count = excluded.seen_count,
        signal_min_percent = excluded.signal_min_percent,
        signal_max_percent = excluded.signal_max_percent,
        signal_avg_percent = excluded.signal_avg_percent,
        signal_latest_percent = excluded.signal_latest_percent,
        latest_channel = excluded.latest_channel,
        channels_json = excluded.channels_json,
        bands_json = excluded.bands_json,
        authentication = excluded.authentication,
        encryption = excluded.encryption,
        last_payload_hash = excluded.last_payload_hash
    `).run(
      bssid,
      locationId,
      locationKey,
      existing?.first_seen_utc ?? tsUtc,
      tsUtc,
      seenCount,
      signalMin,
      signalMax,
      signalAvg,
      signal,
      network.channel,
      JSON.stringify(channels),
      JSON.stringify(bands),
      network.authentication,
      network.encryption,
      payloadHash
    );
    return 1;
  }

  private upsertVendor(network: WindowsWifiNetwork): boolean {
    const vendor = network.mac_enrichment?.vendor;
    const vendorKey = normalizeText(vendor ?? null);
    const oui = normalizeOui(network.mac_enrichment?.oui ?? null);
    if (!vendor || !vendorKey) {
      return false;
    }

    const now = new Date().toISOString();
    this.db.prepare(`
      INSERT INTO vendors (vendor_key, vendor, first_seen_utc, last_seen_utc, device_count, oui_count)
      VALUES (?, ?, ?, ?, 1, ?)
      ON CONFLICT(vendor_key) DO UPDATE SET
        vendor = excluded.vendor,
        last_seen_utc = excluded.last_seen_utc,
        device_count = (
          SELECT COUNT(*) FROM device_inventory WHERE vendor_key = excluded.vendor_key
        ),
        oui_count = (
          SELECT COUNT(*) FROM vendor_ouis WHERE vendor_key = excluded.vendor_key
        )
    `).run(vendorKey, vendor, now, now, oui ? 1 : 0);

    if (oui) {
      this.db.prepare(`
        INSERT INTO vendor_ouis (vendor_key, oui, first_seen_utc, last_seen_utc, seen_count)
        VALUES (?, ?, ?, ?, 1)
        ON CONFLICT(vendor_key, oui) DO UPDATE SET
          last_seen_utc = excluded.last_seen_utc,
          seen_count = vendor_ouis.seen_count + 1
      `).run(vendorKey, oui, now, now);
    }

    return true;
  }

  private saveIdentityAlert(alert: DeviceInventoryAlert, fingerprint: string): void {
    this.db.prepare(`
      INSERT INTO device_identity_alerts (
        alert_type,
        severity,
        identity_fingerprint,
        ssid,
        current_bssid,
        previous_bssid,
        evidence_json,
        created_at_utc
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(alert_type, identity_fingerprint, current_bssid, previous_bssid) DO UPDATE SET
        severity = excluded.severity,
        evidence_json = excluded.evidence_json,
        created_at_utc = excluded.created_at_utc
    `).run(
      alert.alert_type,
      alert.severity,
      fingerprint,
      alert.ssid,
      alert.current_bssid,
      alert.previous_bssid,
      JSON.stringify(alert.evidence),
      alert.created_at_utc
    );
  }
}

async function openDeviceInventoryStore(databaseFile?: string | null): Promise<DeviceInventoryStore> {
  const resolvedFile = resolve(databaseFile ?? DEFAULT_RUN_DATABASE_FILE);
  await mkdir(dirname(resolvedFile), { recursive: true });
  return new DeviceInventoryStore(resolvedFile);
}

function normalizePersistOptions(value?: string | null | DeviceInventoryPersistOptions): DeviceInventoryPersistOptions {
  if (typeof value === 'string' || value === null || value === undefined) {
    return { databaseFile: value ?? null, location: null };
  }

  return {
    databaseFile: value.databaseFile ?? null,
    location: value.location ?? null
  };
}

function scanLocationFromRow(row: ScanLocationRow): ScanLocationRecord {
  return {
    id: row.id,
    location_key: row.location_key,
    label: row.label,
    latitude: row.latitude,
    longitude: row.longitude,
    source: row.source === 'browser' ? 'browser' : 'manual',
    first_seen_utc: row.first_seen_utc,
    last_seen_utc: row.last_seen_utc,
    scan_count: row.scan_count
  };
}

function metricRecordFromRow(row: MetricRow): DeviceMetricRecord {
  const latestNetwork = parseNetworkPayload(row.latest_payload_json ?? null);
  return {
    bssid: row.bssid,
    location_id: row.location_id,
    location_key: row.location_key,
    ssid: row.ssid ?? latestNetwork?.ssid ?? null,
    first_seen_utc: row.first_seen_utc,
    last_seen_utc: row.last_seen_utc,
    seen_count: row.seen_count,
    signal_min_percent: row.signal_min_percent,
    signal_max_percent: row.signal_max_percent,
    signal_avg_percent: row.signal_avg_percent,
    latest_signal_percent: row.signal_latest_percent,
    strongest_signal_percent: row.signal_max_percent,
    average_signal_percent: row.signal_avg_percent === null ? null : Math.round(row.signal_avg_percent),
    latest_channel: row.latest_channel,
    channels: parseNumberArray(row.channels_json),
    bands: parseStringArray(row.bands_json),
    authentication: row.authentication,
    encryption: row.encryption,
    last_payload_hash: row.last_payload_hash,
    latest_network: latestNetwork
  };
}

function mergeInventoryAlerts(network: WindowsWifiNetwork, alerts: DeviceInventoryAlert[]): WindowsWifiNetwork {
  if (alerts.length === 0) {
    return network;
  }

  const existing = network.vulnerability_intel ?? assessNetworkVulnerabilityIntel(network);
  return {
    ...network,
    vulnerability_intel: mergeVulnerabilityIntel(existing, alerts)
  };
}

function mergeVulnerabilityIntel(
  existing: VulnerabilityIntelAssessment,
  alerts: DeviceInventoryAlert[]
): VulnerabilityIntelAssessment {
  const alertSignals = alerts.map(alertToSignal);
  const signals = uniqueSignals([...alertSignals, ...existing.signals]);
  const exposureLevel = maxExposure(existing.exposure_level, alertSignals.length > 0 ? 'review' : 'none');
  const confidence = maxConfidence(existing.confidence, alertSignals.length > 0 ? 'medium' : 'low');

  return {
    ...existing,
    exposure_level: exposureLevel,
    confidence,
    summary:
      alertSignals.length > 0
        ? `Identity review: ${alertSignals[0].summary}`
        : existing.summary,
    signals,
    notes: uniqueStrings([
      ...existing.notes,
      'Saved inventory detected identity-correlation signals from previous AP observations.'
    ])
  };
}

function enrichLookupIntel(
  existing: VulnerabilityIntelAssessment,
  mode: VulnerabilityLookupMode,
  network: WindowsWifiNetwork,
  alerts: DeviceInventoryAlert[],
  scanPlan: VulnerabilityScanPlan
): VulnerabilityIntelAssessment {
  const selectedChecks = scanPlan.checks.filter((check) => check.selected);
  const lookupSignal: VulnerabilityIntelSignal = {
    id: 'lookup.passive_inventory',
    label: 'Passive vulnerability lookup saved',
    severity: 'info',
    confidence: 'medium',
    summary:
      'Saved a passive vulnerability lookup from Windows scan metadata, OUI/vendor hints, security posture, and saved inventory.',
    evidence: [
      `vendor=${network.mac_enrichment?.vendor ?? 'unknown'}`,
      `security=${network.security_assessment?.label ?? 'unknown'}`
    ],
    references: []
  };
  const planSignal: VulnerabilityIntelSignal = {
    id: `lookup.scan_plan.${mode}`,
    label: 'Selected vulnerability lookup plan',
    severity: selectedChecks.some((check) => check.impact === 'low') ? 'low' : 'info',
    confidence: 'high',
    summary: `${selectedChecks.length} safe lookup checks were selected before running ${mode} lookup.`,
    evidence: [
      `selected=${selectedChecks.map((check) => check.id).join(', ') || 'none'}`,
      scanPlan.operator_note ? `operator_note=${scanPlan.operator_note}` : null
    ].filter((item): item is string => Boolean(item)),
    references: []
  };

  return mergeVulnerabilityIntel(
    {
      ...existing,
      signals: uniqueSignals([
        lookupSignal,
        planSignal,
        ...existing.signals
      ]),
      notes: uniqueStrings([
        ...existing.notes,
        'Passive lookup uses existing scan metadata and saved inventory only.',
        'The selected scan plan records expected impact before lookup execution.'
      ])
    },
    alerts
  );
}

function buildVulnerabilityScanPlan(
  mode: VulnerabilityLookupMode,
  options: {
    selectedCheckIds?: string[];
    operatorNote?: string | null;
  }
): VulnerabilityScanPlan {
  const defaultIds = defaultVulnerabilityScanCheckIds(mode);
  const requestedIds = new Set(
    (options.selectedCheckIds?.length ? options.selectedCheckIds : defaultIds)
      .map((id) => id.trim())
      .filter(Boolean)
  );
  const eligibleIds = vulnerabilityScanCheckIdsForMode(mode);
  const checks = VULNERABILITY_SCAN_CHECKS
    .filter((check) => eligibleIds.has(check.id))
    .map((check) => ({
      ...check,
      selected: check.available && requestedIds.has(check.id)
    }));

  return {
    mode,
    selected_check_ids: checks.filter((check) => check.selected).map((check) => check.id),
    checks,
    operator_note: cleanOperatorText(options.operatorNote, 500)
  };
}

function defaultVulnerabilityScanCheckIds(mode: VulnerabilityLookupMode): string[] {
  return [
    'inventory_correlation',
    'radio_security_metadata',
    'vendor_advisory_context',
    'identity_drift_review',
    'pmf_wpa3_capability_review'
  ];
}

function vulnerabilityScanCheckIdsForMode(mode: VulnerabilityLookupMode): Set<string> {
  return PASSIVE_VULNERABILITY_SCAN_CHECK_IDS;
}

function cleanOperatorText(value: string | null | undefined, maxLength: number): string | null {
  if (typeof value !== 'string') {
    return null;
  }

  const trimmed = value.trim().replace(/\s+/g, ' ');
  return trimmed ? trimmed.slice(0, maxLength) : null;
}

function alertToSignal(alert: DeviceInventoryAlert): VulnerabilityIntelSignal {
  return {
    id: `inventory.${alert.alert_type}.${normalizeMacAddress(alert.current_bssid)?.replace(/:/g, '') ?? 'unknown'}`,
    label: 'Possible MAC/BSSID identity change',
    severity: alert.severity,
    confidence: 'medium',
    summary: alert.summary,
    evidence: alert.evidence,
    references: []
  };
}

function historyRecordFromRow(
  row: InventoryRow,
  metrics: MetricRow[],
  nowMs: number,
  newWindowMs: number
): DeviceHistoryRecord {
  const latestPayload = parseNetworkPayload(row.latest_payload_json ?? null);
  const hourCounts = new Map<number, number>();
  const channels = new Set<number>();
  const bands = new Set<string>();
  const signals: number[] = [];

  for (const metric of metrics) {
    for (const tsUtc of [metric.first_seen_utc, metric.last_seen_utc]) {
      const hour = new Date(tsUtc).getHours();
      if (Number.isFinite(hour)) {
        hourCounts.set(hour, (hourCounts.get(hour) ?? 0) + Math.max(1, Math.round(metric.seen_count / 2)));
      }
    }
    for (const channel of parseNumberArray(metric.channels_json)) {
      channels.add(channel);
    }
    if (typeof metric.latest_channel === 'number' && Number.isFinite(metric.latest_channel)) {
      channels.add(metric.latest_channel);
    }
    for (const band of parseStringArray(metric.bands_json)) {
      bands.add(band);
    }
    for (const signal of [metric.signal_min_percent, metric.signal_max_percent, metric.signal_avg_percent, metric.signal_latest_percent]) {
      if (typeof signal === 'number' && Number.isFinite(signal)) {
        signals.push(signal);
      }
    }
  }

  if (latestPayload?.band) {
    bands.add(latestPayload.band);
  }
  if (typeof latestPayload?.channel === 'number' && Number.isFinite(latestPayload.channel)) {
    channels.add(latestPayload.channel);
  }
  if (typeof latestPayload?.signal_percent === 'number' && Number.isFinite(latestPayload.signal_percent)) {
    signals.push(latestPayload.signal_percent);
  }

  const firstSeenMs = Date.parse(row.first_seen_utc);
  const latestBand = latestPayload?.band ?? (bands.size === 1 ? [...bands][0] : null);
  const latestMetric = metrics.slice().sort((left, right) => Date.parse(right.last_seen_utc) - Date.parse(left.last_seen_utc))[0] ?? null;
  const latestChannel = row.latest_channel ?? latestMetric?.latest_channel ?? latestPayload?.channel ?? null;
  const activeHours = [...hourCounts.entries()]
    .map(([hour, count]): DeviceHistoryHourBucket => ({ hour, count }))
    .sort((left, right) => left.hour - right.hour);
  const averageSignal =
    signals.length === 0 ? null : Math.round(signals.reduce((total, signal) => total + signal, 0) / signals.length);
  const strongestSignal = signals.length === 0 ? null : Math.max(...signals);
  const observationCount = metrics.reduce((total, metric) => total + Math.max(0, metric.seen_count), 0);

  return {
    bssid: row.bssid,
    ssid: row.ssid,
    vendor: row.vendor,
    device_hint: row.device_hint,
    mac_scope: row.mac_scope,
    oui: row.oui,
    first_seen_utc: row.first_seen_utc,
    last_seen_utc: row.last_seen_utc,
    seen_count: row.seen_count,
    observation_count: observationCount,
    active_hours: activeHours,
    channels: [...channels].sort((left, right) => left - right),
    bands: [...bands].sort(),
    latest_channel: latestChannel,
    latest_band: latestBand,
    latest_signal_percent: row.latest_signal_percent ?? latestPayload?.signal_percent ?? null,
    strongest_signal_percent: strongestSignal,
    average_signal_percent: averageSignal,
    radio_location_label: formatRadioLocation(latestBand, latestChannel, [...bands], [...channels]),
    is_new: Number.isFinite(firstSeenMs) ? nowMs - firstSeenMs <= newWindowMs : false,
    vulnerability_exposure: latestPayload?.vulnerability_intel?.exposure_level ?? null,
    security_label: latestPayload?.security_assessment?.label ?? null
  };
}

function parseNetworkPayload(value: string | null): WindowsWifiNetwork | null {
  if (!value) {
    return null;
  }

  try {
    const parsed = JSON.parse(value) as unknown;
    if (typeof parsed === 'object' && parsed !== null && (parsed as WindowsWifiNetwork).event_type === 'windows_wifi_network') {
      return parsed as WindowsWifiNetwork;
    }
  } catch {
    return null;
  }

  return null;
}

function parseNumberArray(value: string | null | undefined): number[] {
  if (!value) {
    return [];
  }

  try {
    const parsed = JSON.parse(value) as unknown;
    if (!Array.isArray(parsed)) {
      return [];
    }
    return parsed
      .filter((item): item is number => typeof item === 'number' && Number.isFinite(item))
      .sort((left, right) => left - right);
  } catch {
    return [];
  }
}

function parseStringArray(value: string | null | undefined): string[] {
  if (!value) {
    return [];
  }

  try {
    const parsed = JSON.parse(value) as unknown;
    if (!Array.isArray(parsed)) {
      return [];
    }
    return parsed
      .filter((item): item is string => typeof item === 'string' && item.trim().length > 0)
      .map((item) => item.trim())
      .filter((item, index, values) => values.indexOf(item) === index)
      .sort((left, right) => left.localeCompare(right));
  } catch {
    return [];
  }
}

function sortedNumberUnion(values: number[], nextValue: number | null | undefined): number[] {
  const next = new Set(values.filter((value) => Number.isFinite(value)));
  if (typeof nextValue === 'number' && Number.isFinite(nextValue)) {
    next.add(nextValue);
  }
  return [...next].sort((left, right) => left - right);
}

function sortedStringUnion(values: string[], nextValue: string | null | undefined): string[] {
  const next = new Set(values.map((value) => value.trim()).filter(Boolean));
  if (nextValue?.trim()) {
    next.add(nextValue.trim());
  }
  return [...next].sort((left, right) => left.localeCompare(right));
}

function finiteIntegerOrNull(value: number | null | undefined): number | null {
  return typeof value === 'number' && Number.isFinite(value) ? Math.trunc(value) : null;
}

function hashNetworkPayload(network: WindowsWifiNetwork): string {
  return createHash('sha256')
    .update(JSON.stringify(compactNetworkPayloadForHash(network)))
    .digest('hex');
}

function compactNetworkPayloadForHash(network: WindowsWifiNetwork): Record<string, unknown> {
  return {
    bssid: normalizeMacAddress(network.bssid),
    ssid: network.ssid ?? null,
    authentication: network.authentication ?? null,
    encryption: network.encryption ?? null,
    radio_type: network.radio_type ?? null,
    band: network.band ?? null,
    channel: network.channel ?? null,
    signal_percent: network.signal_percent ?? null,
    native_bss: network.native_bss
      ? {
          phy_type: network.native_bss.phy_type,
          center_frequency_khz: network.native_bss.center_frequency_khz,
          information_elements: network.native_bss.information_elements
        }
      : null,
    mac_enrichment: network.mac_enrichment ?? null,
    security_assessment: network.security_assessment ?? null,
    vulnerability_intel: network.vulnerability_intel ?? null
  };
}

function clampCoordinate(value: number, min: number, max: number): number {
  if (!Number.isFinite(value)) {
    throw new Error('Scan location coordinate is invalid');
  }
  return Math.min(max, Math.max(min, value));
}

function haversineMeters(lat1: number, lng1: number, lat2: number, lng2: number): number {
  const earthRadiusMeters = 6_371_000;
  const lat1Rad = toRadians(lat1);
  const lat2Rad = toRadians(lat2);
  const deltaLat = toRadians(lat2 - lat1);
  const deltaLng = toRadians(lng2 - lng1);
  const a =
    Math.sin(deltaLat / 2) ** 2 +
    Math.cos(lat1Rad) * Math.cos(lat2Rad) * Math.sin(deltaLng / 2) ** 2;
  return earthRadiusMeters * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
}

function toRadians(value: number): number {
  return (value * Math.PI) / 180;
}

function formatRadioLocation(
  latestBand: string | null,
  latestChannel: number | null,
  bands: string[],
  channels: number[]
): string {
  if (latestBand && latestChannel !== null) {
    return `${latestBand} ch ${latestChannel}`;
  }

  if (bands.length > 0 || channels.length > 0) {
    return `${bands.join(', ') || 'band unknown'} | ch ${channels.join(', ') || 'unknown'}`;
  }

  return 'radio location unknown';
}

function identityFingerprint(network: WindowsWifiNetwork): string {
  return [
    normalizeSsid(network.ssid),
    normalizeText(network.mac_enrichment?.vendor ?? null),
    normalizeText(network.mac_enrichment?.device_hint ?? null),
    normalizeText(network.authentication),
    normalizeText(network.encryption),
    normalizeText(network.network_type),
    normalizeText(network.radio_type)
  ].join('|');
}

function isExpectedMeshPeerIdentity(network: WindowsWifiNetwork, row: InventoryRow): boolean {
  if (normalizeSsid(network.ssid) !== normalizeSsid(row.ssid)) {
    return false;
  }

  const protectedNetwork = Boolean(network.authentication && !network.authentication.toLowerCase().includes('open'));
  if (!protectedNetwork) {
    return false;
  }

  const currentHint = normalizeText(network.mac_enrichment?.device_hint ?? null) ?? '';
  const previousHint = normalizeText(row.device_hint) ?? '';
  const currentLooksMesh = looksLikeRouterOrMesh(currentHint) || network.mac_enrichment?.address_scope === 'local';
  const previousLooksMesh = looksLikeRouterOrMesh(previousHint) || row.mac_scope === 'local';

  return currentLooksMesh && previousLooksMesh;
}

function looksLikeRouterOrMesh(value: string): boolean {
  return (
    value.includes('mesh') ||
    value.includes('router') ||
    value.includes('gateway') ||
    value.includes('extender')
  );
}

function normalizeMacAddress(value: string | null | undefined): string | null {
  const hex = value?.replace(/[^a-fA-F0-9]/g, '').toLowerCase() ?? '';
  if (hex.length !== 12) {
    return null;
  }

  return hex.match(/.{1,2}/g)?.join(':') ?? null;
}

function normalizeOui(value: string | null | undefined): string | null {
  const mac = normalizeMacAddress(value);
  if (mac) {
    return mac.split(':').slice(0, 3).join(':');
  }

  const hex = value?.replace(/[^a-fA-F0-9]/g, '').toLowerCase() ?? '';
  if (hex.length !== 6) {
    return null;
  }

  return hex.match(/.{1,2}/g)?.join(':') ?? null;
}

function normalizeSsid(value: string | null | undefined): string | null {
  return normalizeText(value);
}

function normalizeText(value: string | null | undefined): string | null {
  const trimmed = value?.trim().toLowerCase().replace(/\s+/g, ' ') ?? '';
  return trimmed.length > 0 ? trimmed : null;
}

function maxExposure(
  left: VulnerabilityIntelAssessment['exposure_level'],
  right: VulnerabilityIntelAssessment['exposure_level']
): VulnerabilityIntelAssessment['exposure_level'] {
  return EXPOSURE_ORDER[right] > EXPOSURE_ORDER[left] ? right : left;
}

function maxConfidence(
  left: VulnerabilityIntelAssessment['confidence'],
  right: VulnerabilityIntelAssessment['confidence']
): VulnerabilityIntelAssessment['confidence'] {
  return CONFIDENCE_ORDER[right] > CONFIDENCE_ORDER[left] ? right : left;
}

function uniqueSignals(signals: VulnerabilityIntelSignal[]): VulnerabilityIntelSignal[] {
  const seen = new Set<string>();
  return signals.filter((signal) => {
    if (seen.has(signal.id)) {
      return false;
    }
    seen.add(signal.id);
    return true;
  });
}

function uniqueStrings(values: Array<string | null | undefined>): string[] {
  const seen = new Set<string>();
  const result: string[] = [];
  for (const value of values) {
    const trimmed = value?.trim();
    if (!trimmed || seen.has(trimmed)) {
      continue;
    }
    seen.add(trimmed);
    result.push(trimmed);
  }
  return result;
}
