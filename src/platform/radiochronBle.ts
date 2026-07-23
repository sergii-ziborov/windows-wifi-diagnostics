import { getRadioChronCoreClient } from 'radiochron';
import type {
  RadioChronBleFinding,
  RadioChronBleHistory,
  RadioChronBleObservationResult,
  RadioChronBleScanResult,
  RadioChronBleTrackerPolicy,
  RadioChronCoreClient
} from 'radiochron';

export interface DesktopBleScanOptions {
  durationMs?: number;
  zone?: string | null;
}

export interface DesktopBluetoothSystemDevice {
  id: string;
  name: string | null;
  address: string | null;
  transport: 'ble' | 'classic' | 'dual' | 'unknown';
  paired: boolean | null;
  connected: boolean | null;
  category: string | null;
  class_of_device: number | null;
  appearance: number | null;
  source: string;
}

export type DesktopBleRadioScanResult = RadioChronBleScanResult & {
  discovery_mode?: DesktopBleDiscoveryMode;
  system_devices?: DesktopBluetoothSystemDevice[];
};

export type DesktopBleDiscoveryMode = 'active' | 'passive' | 'platform_managed';

export interface DesktopBleScanResult {
  scanned_at_ms: number;
  scan: DesktopBleRadioScanResult;
  observations: RadioChronBleObservationResult[];
  histories: RadioChronBleHistory[];
  findings: RadioChronBleFinding[];
}

export async function scanRadioChronBle(
  options: DesktopBleScanOptions = {},
  client: Pick<RadioChronCoreClient, 'ble'> = getRadioChronCoreClient()
): Promise<DesktopBleScanResult> {
  const scan = await client.ble.scan({ durationMs: options.durationMs }) as DesktopBleRadioScanResult;
  const scannedAtMs = Date.now();
  const monotonicMs = Math.floor(process.uptime() * 1_000);
  const observations: RadioChronBleObservationResult[] = [];

  for (const [index, advertisement] of scan.advertisements.entries()) {
    observations.push(await client.ble.observe({
      monotonic_ms: monotonicMs + index,
      unix_epoch_ms: scannedAtMs,
      context: {
        sensor_id: `radiochron-desktop:${process.platform}:${process.arch}`,
        zone: options.zone ?? null,
        movement_session: null,
        sensor_is_moving: false
      },
      advertisement
    }));
  }

  const [histories, evaluatedFindings] = await Promise.all([
    client.ble.histories(),
    client.ble.evaluate(monotonicMs + scan.advertisements.length)
  ]);

  return {
    scanned_at_ms: scannedAtMs,
    scan,
    observations,
    histories,
    findings: uniqueFindings([
      ...observations.flatMap((observation) => observation.findings),
      ...evaluatedFindings
    ])
  };
}

export async function resetRadioChronBle(
  policy?: RadioChronBleTrackerPolicy
): Promise<{ reset: true }> {
  return getRadioChronCoreClient().ble.resetTracker(policy);
}

function uniqueFindings(findings: RadioChronBleFinding[]): RadioChronBleFinding[] {
  const seen = new Set<string>();
  return findings.filter((finding) => {
    const key = `${finding.kind}:${finding.identity_key ?? ''}:${finding.summary}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}
