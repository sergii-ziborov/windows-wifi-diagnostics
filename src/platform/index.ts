import type { BaselinePlatformAdapter } from '../collector/types';
import { createNativeCorePlatformAdapter } from './nativeCore';
import { createUnsupportedPlatformAdapter } from './unsupported';
import { createWindowsPlatformAdapter } from './windows';

export function createPlatformAdapter(): BaselinePlatformAdapter {
  if (process.platform === 'win32') {
    return createWindowsPlatformAdapter();
  }

  if (process.platform === 'darwin' || process.platform === 'linux') {
    return createNativeCorePlatformAdapter();
  }

  return createUnsupportedPlatformAdapter(process.platform);
}
