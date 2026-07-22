import type {
  BaselinePlatformAdapter,
  CollectorSourceStatus,
  EventContext,
  WindowsWifiEvent
} from '../collector/types';
import {
  getCoreNearbyWifiNetworks,
  getCoreSourceStatus,
  getCoreWifiSnapshots,
  getNativeWifiBssEntries,
  requestNativeWifiScan
} from './rustCore';

export function createNativeCorePlatformAdapter(): BaselinePlatformAdapter {
  return {
    async getSourceStatus() {
      return [await getCoreSourceStatus(), historyUnavailable()];
    },
    async getWlanEventSourceStatus() {
      return [historyUnavailable()];
    },
    getWifiSnapshots(context: EventContext) {
      return getCoreWifiSnapshots(context);
    },
    requestNearbyWifiScan() {
      return requestNativeWifiScan();
    },
    getNearbyWifiBssEntries(context: EventContext) {
      return getNativeWifiBssEntries(context);
    },
    getNearbyWifiNetworks(context: EventContext) {
      return getCoreNearbyWifiNetworks(context);
    },
    async getRecentWlanEvents(_context: EventContext, _maxEvents: number): Promise<WindowsWifiEvent[]> {
      return [];
    }
  };
}

function historyUnavailable(): CollectorSourceStatus {
  return {
    name: 'platform_history',
    available: false,
    detail: 'This platform has no WLAN AutoConfig history; saved RadioChron baselines provide the durable timeline.'
  };
}
