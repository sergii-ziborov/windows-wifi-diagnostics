import type { BaselinePlatformAdapter } from '../collector/types';
import { createUnsupportedPlatformAdapter } from './unsupported';
import { createWindowsPlatformAdapter } from './windows';

export function createPlatformAdapter(): BaselinePlatformAdapter {
  if (process.platform === 'win32') {
    return createWindowsPlatformAdapter();
  }

  return createUnsupportedPlatformAdapter(process.platform);
}
