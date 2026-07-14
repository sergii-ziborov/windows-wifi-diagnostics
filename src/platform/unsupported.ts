import type {
  BaselinePlatformAdapter,
  CollectorSourceStatus,
  EventContext,
  WindowsWifiEvent,
  WindowsWifiSnapshot
} from '../collector/types';

export function createUnsupportedPlatformAdapter(platform: NodeJS.Platform): BaselinePlatformAdapter {
  const sourceStatus: CollectorSourceStatus = {
    name: 'platform_adapter',
    available: false,
    detail: `Platform ${platform} is not implemented in phase 1`
  };

  return {
    async getSourceStatus(): Promise<CollectorSourceStatus[]> {
      return [sourceStatus];
    },
    async getWlanEventSourceStatus(): Promise<CollectorSourceStatus[]> {
      return [sourceStatus];
    },
    async getWifiSnapshots(_context: EventContext): Promise<WindowsWifiSnapshot[]> {
      return [];
    },
    async getNearbyWifiNetworks(_context: EventContext) {
      return [];
    },
    async getRecentWlanEvents(
      _context: EventContext,
      _maxEvents: number
    ): Promise<WindowsWifiEvent[]> {
      return [];
    }
  };
}
