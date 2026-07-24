import type {
  RadioChronBleAddressType,
  RadioChronBleIdentityConfidence,
  RadioChronBleManufacturerData,
  RadioChronBleServiceData
} from 'radiochron';
import type {
  DesktopBleHistoryArchive,
  DesktopBleHistoryPoint,
  DesktopBleViewResult
} from '../../platform/bleHistory';
import {
  blePointTrackingKey,
  type BleTrackingConfidence
} from '../../platform/bleIdentityTracking';

export interface BleWorkspaceDevice {
  key: string;
  identityKey: string;
  identityConfidence: RadioChronBleIdentityConfidence | 'system_inventory';
  trackingConfidence: BleTrackingConfidence;
  protocol: string | null;
  currentAddress: string | null;
  addressType: RadioChronBleAddressType;
  localName: string | null;
  rssiDbm: number | null;
  txPowerDbm: number | null;
  connectable: boolean | null;
  serviceUuids: string[];
  manufacturerData: RadioChronBleManufacturerData[];
  serviceData: RadioChronBleServiceData[];
  protocolIdentity: string | null;
  firstSeenMs: number | null;
  lastSeenMs: number | null;
  observationCount: number;
  zones: string[];
  retainedOnly: boolean;
  radioObserved: boolean;
  systemId: string | null;
  transport: 'ble' | 'classic' | 'dual' | 'unknown' | null;
  paired: boolean | null;
  connected: boolean | null;
  systemCategory: string | null;
  systemAppearance: number | null;
  inventorySource: string | null;
  mergeConfidence: 'exact_address' | 'system_only' | null;
}

export function buildBleWorkspaceDevices(
  result: DesktopBleViewResult | null,
  history: DesktopBleHistoryArchive | null
): BleWorkspaceDevice[] {
  const retained = retainedDeviceMap(history);
  const retainedSystem = retainedSystemDeviceMap(history);
  const currentTracking = currentTrackingMap(result, history);
  const devices: BleWorkspaceDevice[] = (result?.scan.advertisements ?? []).map((advertisement, index): BleWorkspaceDevice => {
    const observation = result?.observations[index];
    const proposedKey = observation?.identity.key ?? advertisement.protocol_identity ?? advertisement.address;
    const trackedPoint = currentTracking.get(proposedKey);
    const trackingKey = trackedPoint?.trackingKey
      ?? matchingRetainedKey(proposedKey, advertisement.protocol_identity ?? null, retained)
      ?? proposedKey;
    const coreHistory = result?.histories.find((item) => item.identity.key === proposedKey);
    const retainedDevice = retained.get(trackingKey);
    retained.delete(trackingKey);
    return {
      key: trackingKey,
      identityKey: proposedKey,
      identityConfidence: observation?.identity.confidence ?? identityConfidenceForAddress(advertisement.address_type),
      trackingConfidence: trackedPoint?.trackingConfidence
        ?? retainedDevice?.trackingConfidence
        ?? trackingConfidenceForIdentity(observation?.identity.confidence),
      protocol: observation?.identity.protocol ?? null,
      currentAddress: advertisement.address,
      addressType: advertisement.address_type,
      localName: advertisement.local_name ?? retainedDevice?.localName ?? null,
      rssiDbm: advertisement.rssi_dbm,
      txPowerDbm: advertisement.tx_power_dbm ?? null,
      connectable: advertisement.connectable ?? null,
      serviceUuids: advertisement.service_uuids ?? [],
      manufacturerData: advertisement.manufacturer_data ?? [],
      serviceData: advertisement.service_data ?? [],
      protocolIdentity: advertisement.protocol_identity ?? null,
      firstSeenMs: coreHistory?.first_seen_ms ?? retainedDevice?.firstSeenMs ?? null,
      lastSeenMs: coreHistory?.last_seen_ms ?? retainedDevice?.lastSeenMs ?? result?.scanned_at_ms ?? null,
      observationCount: coreHistory?.observation_count ?? retainedDevice?.observationCount ?? 1,
      zones: retainedDevice?.zones ?? [],
      retainedOnly: false,
      radioObserved: true,
      systemId: null,
      transport: 'ble',
      paired: null,
      connected: null,
      systemCategory: null,
      systemAppearance: null,
      inventorySource: null,
      mergeConfidence: null
    };
  });

  const byAddress = new Map(devices
    .filter((device) => device.currentAddress)
    .map((device) => [normalizedAddress(device.currentAddress), device]));
  for (const systemDevice of result?.scan.system_devices ?? []) {
    const retainedSystemDevice = retainedSystem.get(systemDevice.id);
    retainedSystem.delete(systemDevice.id);
    const matched = systemDevice.address
      ? byAddress.get(normalizedAddress(systemDevice.address))
      : undefined;
    if (matched) {
      matched.localName = systemDevice.name ?? matched.localName;
      matched.systemId = systemDevice.id;
      matched.transport = systemDevice.transport;
      matched.paired = systemDevice.paired;
      matched.connected = systemDevice.connected;
      matched.systemCategory = systemDevice.category;
      matched.systemAppearance = systemDevice.appearance;
      matched.inventorySource = systemDevice.source;
      matched.mergeConfidence = 'exact_address';
      matched.firstSeenMs = retainedSystemDevice?.firstSeenMs ?? matched.firstSeenMs;
      matched.observationCount = Math.max(matched.observationCount, retainedSystemDevice?.observationCount ?? 1);
      matched.zones = [...new Set([...matched.zones, ...(retainedSystemDevice?.zones ?? [])])].sort();
      continue;
    }
    devices.push({
      key: `system:${systemDevice.id}`,
      identityKey: `system:${systemDevice.id}`,
      identityConfidence: 'system_inventory',
      trackingConfidence: 'stable_identity',
      protocol: null,
      currentAddress: systemDevice.address,
      addressType: 'unknown',
      localName: systemDevice.name,
      rssiDbm: null,
      txPowerDbm: null,
      connectable: null,
      serviceUuids: [],
      manufacturerData: [],
      serviceData: [],
      protocolIdentity: null,
      firstSeenMs: retainedSystemDevice?.firstSeenMs ?? result?.scanned_at_ms ?? null,
      lastSeenMs: result?.scanned_at_ms ?? null,
      observationCount: (retainedSystemDevice?.observationCount ?? 0) + 1,
      zones: retainedSystemDevice?.zones ?? [],
      retainedOnly: false,
      radioObserved: false,
      systemId: systemDevice.id,
      transport: systemDevice.transport,
      paired: systemDevice.paired,
      connected: systemDevice.connected,
      systemCategory: systemDevice.category,
      systemAppearance: systemDevice.appearance,
      inventorySource: systemDevice.source,
      mergeConfidence: 'system_only'
    });
  }

  const retainedDevices = [...retained.values()].filter((device) =>
    device.identityConfidence !== 'ephemeral_address' || device.observationCount > 1
  );
  return [...devices, ...retainedDevices, ...retainedSystem.values()].sort(compareDevices);
}

function retainedDeviceMap(history: DesktopBleHistoryArchive | null): Map<string, BleWorkspaceDevice> {
  const points = new Map<string, { point: DesktopBleHistoryPoint; first: number; last: number; count: number; zones: Set<string> }>();
  for (const session of history?.sessions ?? []) {
    for (const point of session.points) {
      const trackingKey = blePointTrackingKey(point);
      const current = points.get(trackingKey);
      const zones = current?.zones ?? new Set<string>();
      if (session.zone) zones.add(session.zone);
      points.set(trackingKey, {
        point,
        first: Math.min(current?.first ?? session.observed_at_ms, session.observed_at_ms),
        last: Math.max(current?.last ?? session.observed_at_ms, session.observed_at_ms),
        count: (current?.count ?? 0) + 1,
        zones
      });
    }
  }

  return new Map([...points.entries()].map(([trackingKey, item]) => [trackingKey, {
    key: trackingKey,
    identityKey: item.point.identity_key,
    identityConfidence: item.point.identity_confidence,
    trackingConfidence: item.point.tracking_confidence ?? trackingConfidenceForIdentity(item.point.identity_confidence),
    protocol: item.point.protocol,
    currentAddress: null,
    addressType: item.point.address_type,
    localName: item.point.local_name,
    rssiDbm: item.point.rssi_dbm,
    txPowerDbm: item.point.tx_power_dbm ?? null,
    connectable: item.point.connectable ?? null,
    serviceUuids: item.point.service_uuids ?? [],
    manufacturerData: (item.point.company_ids ?? []).map((company_id) => ({ company_id, data: [] })),
    serviceData: (item.point.service_data_uuids ?? []).map((uuid) => ({ uuid, data: [] })),
    protocolIdentity: null,
    firstSeenMs: item.first,
    lastSeenMs: item.last,
    observationCount: item.count,
    zones: [...item.zones].sort(),
    retainedOnly: true,
    radioObserved: false,
    systemId: null,
    transport: 'ble',
    paired: null,
    connected: null,
    systemCategory: null,
    systemAppearance: null,
    inventorySource: null,
    mergeConfidence: null
  }]));
}

function retainedSystemDeviceMap(history: DesktopBleHistoryArchive | null): Map<string, BleWorkspaceDevice> {
  const devices = new Map<string, BleWorkspaceDevice>();
  for (const session of history?.sessions ?? []) {
    for (const point of session.system_devices ?? []) {
      const current = devices.get(point.id);
      devices.set(point.id, {
        key: `system:${point.id}`,
        identityKey: `system:${point.id}`,
        identityConfidence: 'system_inventory',
        trackingConfidence: 'stable_identity',
        protocol: null,
        currentAddress: null,
        addressType: 'unknown',
        localName: point.name ?? current?.localName ?? null,
        rssiDbm: null,
        txPowerDbm: null,
        connectable: null,
        serviceUuids: [],
        manufacturerData: [],
        serviceData: [],
        protocolIdentity: null,
        firstSeenMs: current?.firstSeenMs ?? session.observed_at_ms,
        lastSeenMs: session.observed_at_ms,
        observationCount: (current?.observationCount ?? 0) + 1,
        zones: [...new Set([...(current?.zones ?? []), ...(session.zone ? [session.zone] : [])])].sort(),
        retainedOnly: true,
        radioObserved: false,
        systemId: point.id,
        transport: point.transport,
        paired: point.paired,
        connected: point.connected,
        systemCategory: point.category,
        systemAppearance: point.appearance,
        inventorySource: 'retained-system-inventory',
        mergeConfidence: 'system_only'
      });
    }
  }
  return devices;
}

function currentTrackingMap(
  result: DesktopBleViewResult | null,
  history: DesktopBleHistoryArchive | null
): Map<string, { trackingKey: string; trackingConfidence: BleTrackingConfidence }> {
  if (!result) return new Map();
  const session = [...(history?.sessions ?? [])]
    .reverse()
    .find((item) => item.observed_at_ms === result.scanned_at_ms);
  return new Map((session?.points ?? []).map((point) => [point.identity_key, {
    trackingKey: blePointTrackingKey(point),
    trackingConfidence: point.tracking_confidence ?? trackingConfidenceForIdentity(point.identity_confidence)
  }]));
}

function identityConfidenceForAddress(addressType: RadioChronBleAddressType): RadioChronBleIdentityConfidence {
  return addressType === 'public' || addressType === 'random_static'
    ? 'static_address'
    : 'ephemeral_address';
}

function trackingConfidenceForIdentity(
  confidence: RadioChronBleIdentityConfidence | undefined
): BleTrackingConfidence {
  return confidence === 'ephemeral_address' ? 'single_observation' : 'stable_identity';
}

function matchingRetainedKey(
  proposedKey: string,
  protocolIdentity: string | null,
  retained: Map<string, BleWorkspaceDevice>
): string | null {
  if (retained.has(proposedKey)) return proposedKey;
  if (!protocolIdentity) return null;
  const protocolToken = identityToken(protocolIdentity);
  return [...retained.keys()].find((key) => identityToken(key).endsWith(protocolToken)) ?? null;
}

function identityToken(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9]/g, '');
}

function normalizedAddress(value: string | null): string {
  return value?.toLowerCase().replace(/[^a-f0-9]/g, '') ?? '';
}

function compareDevices(left: BleWorkspaceDevice, right: BleWorkspaceDevice): number {
  if (left.connected !== right.connected) return Number(right.connected === true) - Number(left.connected === true);
  if (left.rssiDbm !== null || right.rssiDbm !== null) {
    return (right.rssiDbm ?? -200) - (left.rssiDbm ?? -200);
  }
  if (left.paired !== right.paired) return Number(right.paired === true) - Number(left.paired === true);
  return (left.localName ?? left.key).localeCompare(right.localName ?? right.key);
}
