import type { BleWorkspaceDevice } from './bleWorkspaceModel';
import assignedNumbers from './generated/bleAssignedNumbers.json';

export interface BleDeviceIntelligence {
  displayName: string;
  vendor: string | null;
  vendorSource: 'company_id' | 'name_hint' | 'unknown';
  companyIds: number[];
  category: string;
  confidence: 'high' | 'medium' | 'low';
  protocols: string[];
  services: Array<{ uuid: string; name: string; category: string }>;
  evidence: string[];
  privacyLabel: string;
}

interface AssignedNumbersData {
  metadata: {
    source_commit: string;
    source_commit_date: string;
    counts: { companies: number; services: number; appearances: number };
  };
  companies: Record<string, string>;
  services: Record<string, { name: string; source: string }>;
  appearances: Record<string, string>;
}

const DATABASE = assignedNumbers as AssignedNumbersData;
const COMPANY_NAMES = DATABASE.companies;
const SERVICES = DATABASE.services;
const APPEARANCES = DATABASE.appearances;

export function analyzeBleDevice(device: BleWorkspaceDevice): BleDeviceIntelligence {
  const companyIds = [...new Set(device.manufacturerData.map((item) => item.company_id))];
  const company = companyIds.map((id) => COMPANY_NAMES[String(id)]).find(Boolean) ?? null;
  const serviceUuids = [...new Set([
    ...device.serviceUuids,
    ...device.serviceData.map((item) => item.uuid)
  ])];
  const services = serviceUuids.map((uuid) => {
    const key = assignedUuidKey(uuid);
    const assigned = SERVICES[key];
    const name = assigned?.name ?? `Custom service ${shortUuid(uuid)}`;
    return { uuid, name, category: assigned ? categoryForService(name) : 'Custom' };
  });
  const protocols = inferProtocols(device);
  const nameHint = inferVendorFromName(device.localName);
  const vendor = company ?? nameHint;
  const appearance = bleAppearanceName(device.systemAppearance);
  const category = cleanText(device.systemCategory) ?? appearance ?? inferCategory(device, services, protocols);
  const unresolvedCompanyIds = companyIds.filter((id) => !COMPANY_NAMES[String(id)]);
  const evidence = [
    device.inventorySource ? `Friendly name, connection state and type came from ${device.inventorySource}.` : null,
    device.mergeConfidence === 'exact_address' ? 'System inventory and radio evidence were joined by an exact Bluetooth address.' : null,
    device.mergeConfidence === 'system_only' ? 'This system device was not observed advertising during the current scan.' : null,
    company ? `Manufacturer data company ID resolves to ${company}.` : null,
    unresolvedCompanyIds.length
      ? `Manufacturer data includes unassigned or unresolved ID${unresolvedCompanyIds.length === 1 ? '' : 's'} ${unresolvedCompanyIds.map(formatCompanyId).join(', ')}.`
      : null,
    appearance ? `System appearance ${device.systemAppearance} resolves to ${appearance}.` : null,
    services.length ? `${services.length} advertised service${services.length === 1 ? '' : 's'} classified.` : null,
    protocols.length ? `Advertisement signature: ${protocols.join(', ')}.` : null,
    device.connectable === true ? 'The current advertisement reports a connectable peripheral.' : null,
    device.retainedOnly ? 'This identity is retained history; no current radio address is stored.' : null
  ].filter((item): item is string => Boolean(item));
  return {
    displayName: displayNameForDevice(device, vendor, services, protocols, unresolvedCompanyIds),
    vendor,
    vendorSource: company ? 'company_id' : nameHint ? 'name_hint' : 'unknown',
    companyIds,
    category,
    confidence: device.localName && device.inventorySource
      ? 'high'
      : company || protocols.length ? 'high' : services.length || nameHint ? 'medium' : 'low',
    protocols,
    services,
    evidence,
    privacyLabel: device.systemId && !device.radioObserved
      ? 'System inventory; radio address behavior not observed'
      : privacyLabel(device.addressType)
  };
}

export function bleCompanyName(companyId: number): string | null {
  return COMPANY_NAMES[String(companyId)] ?? null;
}

export function bleAppearanceName(appearance: number | null | undefined): string | null {
  if (appearance === null || appearance === undefined || !Number.isFinite(appearance)) return null;
  return APPEARANCES[String(appearance)] ?? APPEARANCES[String(appearance & 0xffc0)] ?? null;
}

export function bleAssignedNumbersMetadata(): AssignedNumbersData['metadata'] {
  return DATABASE.metadata;
}

function inferProtocols(device: BleWorkspaceDevice): string[] {
  const protocols = new Set<string>();
  for (const uuid of [...device.serviceUuids, ...device.serviceData.map((item) => item.uuid)]) {
    const key = assignedUuidKey(uuid);
    if (key === 'feaa') protocols.add('Eddystone');
    if (key === 'fe2c') protocols.add('Google Fast Pair');
    if (key === 'fd6f') protocols.add('Exposure Notification');
  }
  for (const item of device.manufacturerData) {
    if (item.company_id === 0x004c && item.data[0] === 0x02 && item.data[1] === 0x15) protocols.add('iBeacon');
    else if (item.company_id === 0x004c) protocols.add('Apple Continuity');
    if (item.company_id === 0x0006) protocols.add('Microsoft Bluetooth advertisement');
    if (item.data[0] === 0xbe && item.data[1] === 0xac) protocols.add('AltBeacon');
  }
  if (device.protocolIdentity) protocols.add(device.protocolIdentity);
  return [...protocols];
}

function inferCategory(
  device: BleWorkspaceDevice,
  services: BleDeviceIntelligence['services'],
  protocols: string[]
): string {
  if (protocols.some((item) => /beacon/i.test(item))) return 'Beacon / tracker';
  const preferred = ['Medical', 'Health / fitness', 'Audio', 'Input device', 'Sensor', 'Navigation', 'Accessory', 'Safety'];
  const serviceCategory = preferred.find((candidate) => services.some((item) => item.category === candidate));
  if (serviceCategory) return serviceCategory;
  const name = device.localName?.toLowerCase() ?? '';
  if (/airpods|buds|head(phone|set)|speaker|sound|jabra|bose/.test(name)) return 'Audio';
  if (/watch|band|fit|heart|scale|thermo/.test(name)) return 'Health / fitness';
  if (/keyboard|mouse|trackpad|controller|gamepad/.test(name)) return 'Input device';
  if (/tag|tile|beacon|tracker/.test(name)) return 'Beacon / tracker';
  if (/sensor|meter|temp|humidity/.test(name)) return 'Sensor';
  if (device.connectable === true) return 'Connectable peripheral';
  return 'Identity not advertised';
}

function displayNameForDevice(
  device: BleWorkspaceDevice,
  vendor: string | null,
  services: BleDeviceIntelligence['services'],
  protocols: string[],
  unresolvedCompanyIds: number[]
): string {
  const localName = cleanText(device.localName);
  if (localName) return localName;
  if (protocols.includes('iBeacon')) return vendor ? `${vendor} iBeacon` : 'iBeacon';
  if (protocols.includes('Eddystone')) return 'Eddystone beacon';
  if (vendor) return `${vendor} Bluetooth device`;
  const descriptiveService = services.find((service) => !['System', 'Custom'].includes(service.category));
  if (descriptiveService) return `${descriptiveService.name} device`;
  if (unresolvedCompanyIds.length) return `Unresolved manufacturer ${formatCompanyId(unresolvedCompanyIds[0])}`;
  if (device.addressType === 'resolvable_private' || device.addressType === 'non_resolvable_private') {
    return 'Anonymous private BLE advertiser';
  }
  if (device.addressType === 'public') return 'Unidentified public BLE device';
  return 'Unidentified Bluetooth device';
}

function categoryForService(name: string): string {
  if (/glucose|blood|health|thermometer|oximeter|insulin|weight|body composition/i.test(name)) return 'Medical';
  if (/heart|fitness|cycling|running|activity/i.test(name)) return 'Health / fitness';
  if (/audio|media|microphone|volume|hearing|voice assistant/i.test(name)) return 'Audio';
  if (/human interface|hid|scan parameters/i.test(name)) return 'Input device';
  if (/sensor|measurement|environment/i.test(name)) return 'Sensor';
  if (/location|navigation|positioning|ranging/i.test(name)) return 'Navigation';
  if (/alert|emergency|link loss/i.test(name)) return 'Safety';
  if (/generic|attribute|device information|battery|time|power/i.test(name)) return 'System';
  return 'Accessory';
}

function inferVendorFromName(localName: string | null): string | null {
  const name = localName?.toLowerCase() ?? '';
  const hints: Array<[RegExp, string]> = [
    [/airpods|iphone|ipad|apple|beats/, 'Apple'],
    [/galaxy|samsung/, 'Samsung Electronics'],
    [/pixel|google|nest/, 'Google'],
    [/fitbit/, 'Fitbit / Google'],
    [/xiaomi|mi band|redmi/, 'Xiaomi'],
    [/tile/, 'Tile'],
    [/bose/, 'Bose'],
    [/jabra/, 'GN Audio'],
    [/garmin/, 'Garmin']
  ];
  return hints.find(([pattern]) => pattern.test(name))?.[1] ?? null;
}

function privacyLabel(addressType: BleWorkspaceDevice['addressType']): string {
  if (addressType === 'resolvable_private') return 'Rotating private address';
  if (addressType === 'non_resolvable_private') return 'Non-resolvable private address';
  if (addressType === 'random_static') return 'Random static address';
  if (addressType === 'public') return 'Public device address';
  return 'Address privacy unknown';
}

function assignedUuidKey(uuid: string): string {
  const normalized = uuid.toLowerCase().replace(/[{}]/g, '');
  const match = normalized.match(/^0000([0-9a-f]{4})-0000-1000-8000-00805f9b34fb$/);
  if (match) return match[1];
  return normalized;
}

function shortUuid(uuid: string): string {
  const key = assignedUuidKey(uuid);
  return (key.length > 8 ? key.slice(0, 8) : key).toUpperCase();
}

function formatCompanyId(companyId: number): string {
  return `0x${companyId.toString(16).toUpperCase().padStart(4, '0')}`;
}

function cleanText(value: string | null | undefined): string | null {
  const normalized = value?.trim();
  if (!normalized || /^(undefined|null|unknown)$/i.test(normalized)) return null;
  return normalized;
}
