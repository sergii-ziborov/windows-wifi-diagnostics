import { performance } from 'node:perf_hooks';
import type { ConnectivityCheckResult } from './types';

const TRACE_URL = 'https://cloudflare.com/cdn-cgi/trace';
const DOWNLOAD_URL = 'https://speed.cloudflare.com/__down';
const DEFAULT_DOWNLOAD_BYTES = 750_000;
const DEFAULT_TIMEOUT_MS = 8_000;

export interface ConnectivityCheckOptions {
  downloadBytes?: number;
  timeoutMs?: number;
  fetchImpl?: typeof fetch;
  now?: Date;
}

export async function checkInternetConnectivity(
  options: ConnectivityCheckOptions = {}
): Promise<ConnectivityCheckResult> {
  const fetchImpl = options.fetchImpl ?? fetch;
  const now = options.now ?? new Date();
  const downloadBytes = boundedInteger(options.downloadBytes, DEFAULT_DOWNLOAD_BYTES, 128_000, 5_000_000);
  const timeoutMs = boundedInteger(options.timeoutMs, DEFAULT_TIMEOUT_MS, 2_000, 20_000);
  let publicIp: string | null = null;
  let latencyMs: number | null = null;
  let downloadMbps: number | null = null;
  let downloadElapsedMs: number | null = null;
  const errors: string[] = [];

  try {
    const trace = await timedFetchText(fetchImpl, TRACE_URL, timeoutMs);
    latencyMs = trace.elapsedMs;
    publicIp = parseCloudflareTraceIp(trace.text);
  } catch (error: unknown) {
    errors.push(`latency: ${formatConnectivityError(error)}`);
  }

  try {
    const download = await timedDownload(fetchImpl, `${DOWNLOAD_URL}?bytes=${downloadBytes}&t=${Date.now()}`, timeoutMs);
    downloadElapsedMs = download.elapsedMs;
    downloadMbps = download.elapsedMs > 0 ? roundTo((download.bytes * 8) / (download.elapsedMs / 1000) / 1_000_000, 2) : null;
  } catch (error: unknown) {
    errors.push(`download: ${formatConnectivityError(error)}`);
  }

  const status: ConnectivityCheckResult['status'] =
    latencyMs === null && downloadMbps === null ? 'offline' : errors.length > 0 ? 'degraded' : 'online';

  return {
    schema: 'monitor.connectivity_check.v1',
    ts_utc: now.toISOString(),
    provider: 'cloudflare',
    status,
    public_ip: publicIp,
    latency_ms: latencyMs,
    download_mbps: downloadMbps,
    download_bytes: downloadBytes,
    download_elapsed_ms: downloadElapsedMs,
    error: errors.length > 0 ? errors.join('; ') : null
  };
}

async function timedFetchText(
  fetchImpl: typeof fetch,
  url: string,
  timeoutMs: number
): Promise<{ text: string; elapsedMs: number }> {
  const startedAt = performance.now();
  const response = await fetchWithTimeout(fetchImpl, url, timeoutMs);
  if (!response.ok) {
    throw new Error(`HTTP ${response.status}`);
  }

  const text = await response.text();
  return {
    text,
    elapsedMs: Math.round(performance.now() - startedAt)
  };
}

async function timedDownload(
  fetchImpl: typeof fetch,
  url: string,
  timeoutMs: number
): Promise<{ bytes: number; elapsedMs: number }> {
  const startedAt = performance.now();
  const response = await fetchWithTimeout(fetchImpl, url, timeoutMs);
  if (!response.ok) {
    throw new Error(`HTTP ${response.status}`);
  }

  const buffer = await response.arrayBuffer();
  return {
    bytes: buffer.byteLength,
    elapsedMs: Math.round(performance.now() - startedAt)
  };
}

async function fetchWithTimeout(fetchImpl: typeof fetch, url: string, timeoutMs: number): Promise<Response> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);

  try {
    return await fetchImpl(url, {
      signal: controller.signal,
      headers: {
        'cache-control': 'no-cache'
      }
    });
  } finally {
    clearTimeout(timeout);
  }
}

function parseCloudflareTraceIp(value: string): string | null {
  const line = value.split(/\r?\n/).find((entry) => entry.startsWith('ip='));
  return line ? line.slice(3).trim() || null : null;
}

function boundedInteger(value: unknown, fallback: number, min: number, max: number): number {
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    return fallback;
  }

  return Math.min(max, Math.max(min, Math.trunc(value)));
}

function formatConnectivityError(error: unknown): string {
  if (error instanceof Error) {
    return error.name === 'AbortError' ? 'timeout' : error.message;
  }

  return String(error);
}

function roundTo(value: number, digits: number): number {
  const factor = 10 ** digits;
  return Math.round(value * factor) / factor;
}
