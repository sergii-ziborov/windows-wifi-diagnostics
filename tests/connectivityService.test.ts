import { describe, expect, it } from 'vitest';
import { checkInternetConnectivity } from '../src/collector/connectivityService';

describe('checkInternetConnectivity', () => {
  it('reports online with public IP and download speed', async () => {
    const fetchImpl = async (url: string | URL | Request) => {
      const textUrl = String(url);
      if (textUrl.includes('/cdn-cgi/trace')) {
        return new Response('ip=203.0.113.10\nloc=IL\n');
      }

      return new Response(new Uint8Array(250_000));
    };

    const result = await checkInternetConnectivity({
      fetchImpl: fetchImpl as typeof fetch,
      downloadBytes: 250_000,
      now: new Date('2026-06-04T10:00:00.000Z')
    });

    expect(result).toMatchObject({
      schema: 'monitor.connectivity_check.v1',
      ts_utc: '2026-06-04T10:00:00.000Z',
      provider: 'cloudflare',
      status: 'online',
      public_ip: '203.0.113.10',
      download_bytes: 250_000,
      error: null
    });
    expect(result.download_mbps).toBeGreaterThan(0);
  });

  it('returns offline instead of throwing when both checks fail', async () => {
    const fetchImpl = async () => {
      throw new Error('network down');
    };

    const result = await checkInternetConnectivity({
      fetchImpl: fetchImpl as unknown as typeof fetch,
      now: new Date('2026-06-04T10:00:00.000Z')
    });

    expect(result.status).toBe('offline');
    expect(result.error).toContain('latency: network down');
    expect(result.error).toContain('download: network down');
  });
});
