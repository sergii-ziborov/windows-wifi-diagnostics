import type { EventContext, WindowsWifiEvent } from '../../collector/types';

interface RawWlanEvent {
  TimeCreated?: string;
  Id?: number;
  RecordId?: number;
  ProviderName?: string;
  LevelDisplayName?: string;
  Message?: string;
}

export const WLAN_AUTOCONFIG_LOG = 'Microsoft-Windows-WLAN-AutoConfig/Operational';

export function parseWlanAutoConfigEvents(
  jsonOutput: string,
  context: EventContext
): WindowsWifiEvent[] {
  const trimmed = jsonOutput.trim();
  if (!trimmed) {
    return [];
  }

  const parsed = JSON.parse(trimmed) as RawWlanEvent | RawWlanEvent[] | null;
  const rawEvents = Array.isArray(parsed) ? parsed : parsed ? [parsed] : [];

  return rawEvents.map((event) => {
    const message = event.Message ?? '';
    const messageFields = parseMessageFields(message);

    return {
      schema: 'wifi.windows_baseline.v1',
      event_type: 'windows_wifi_event',
      ts_utc: parsePowerShellDate(event.TimeCreated),
      source: 'baseline',
      run_id: context.runId,
      host_id: context.hostId,
      event_id: Number(event.Id ?? 0),
      record_id: event.RecordId ?? null,
      provider_name: event.ProviderName ?? null,
      level: event.LevelDisplayName ?? null,
      adapter: value(messageFields, 'Network Adapter'),
      interface_guid: value(messageFields, 'Interface GUID'),
      local_mac: normalizeMac(value(messageFields, 'Local MAC Address')),
      ssid: value(messageFields, 'SSID') ?? value(messageFields, 'Network SSID'),
      bss_type: value(messageFields, 'BSS Type'),
      message_fields: messageFields,
      raw_message: message
    };
  });
}

export function buildWlanEventsScript(maxEvents: number): string {
  const safeMaxEvents = Math.max(1, Math.floor(maxEvents));

  return [
    `$events = @(Get-WinEvent -LogName '${WLAN_AUTOCONFIG_LOG}' -MaxEvents ${safeMaxEvents} |`,
    'Select-Object TimeCreated,Id,RecordId,ProviderName,LevelDisplayName,Message);',
    '$events | ConvertTo-Json -Depth 5 -Compress'
  ].join(' ');
}

export function parseMessageFields(message: string): Record<string, string> {
  const fields: Record<string, string> = {};

  for (const line of message.split(/\r?\n/)) {
    const match = line.match(/^\s*([^:]+?)\s*:\s*(.*?)\s*$/);
    if (!match) {
      continue;
    }

    fields[match[1].trim()] = match[2].trim();
  }

  return fields;
}

function parsePowerShellDate(value: string | undefined): string {
  if (!value) {
    return new Date(0).toISOString();
  }

  const microsoftDate = value.match(/\/Date\((\d+)\)\//);
  if (microsoftDate) {
    return new Date(Number(microsoftDate[1])).toISOString();
  }

  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    return new Date(0).toISOString();
  }

  return parsed.toISOString();
}

function value(fields: Record<string, string>, key: string): string | null {
  const found = fields[key];
  return found && found.length > 0 ? found : null;
}

function normalizeMac(input: string | null): string | null {
  if (!input) {
    return null;
  }

  return input.trim().replace(/-/g, ':').toLowerCase();
}
