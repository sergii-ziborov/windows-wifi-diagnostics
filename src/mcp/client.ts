import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { existsSync } from 'node:fs';
import { join, resolve } from 'node:path';

/**
 * Minimal MCP stdio client for the BeaconTrail server.
 *
 * BeaconTrail is the Rust engine that replaced this app's runtime-compiled C#
 * (`Add-Type` against `wlanapi.dll`). It speaks newline-delimited JSON-RPC 2.0,
 * so the client is a framing loop and a pending-request map — no SDK needed.
 *
 * One long-lived child process is reused: the handshake costs ~60 ms and the
 * server is stateless, so re-spawning per call would be pure overhead.
 */

const PROTOCOL_VERSION = '2025-06-18';
const DEFAULT_TIMEOUT_MS = 15_000;

interface PendingRequest {
  resolve: (result: unknown) => void;
  reject: (error: Error) => void;
  timer: ReturnType<typeof setTimeout>;
}

interface JsonRpcResponse {
  id?: number;
  result?: { content?: Array<{ type: string; text?: string }>; isError?: boolean };
  error?: { code: number; message: string };
}

/**
 * Locate the server binary.
 *
 * Explicit configuration wins, then the packaged copy, then the sibling
 * development checkout, and finally whatever is on PATH.
 */
export function resolveBeaconTrailPath(): string {
  const configured = process.env.BEACONTRAIL_MCP?.trim();
  if (configured) {
    return configured;
  }

  const candidates = [
    join(process.resourcesPath ?? '', 'beacontrail.exe'),
    resolve(process.cwd(), '..', 'beacontrail', 'target', 'release', 'beacontrail.exe')
  ];

  for (const candidate of candidates) {
    if (candidate && existsSync(candidate)) {
      return candidate;
    }
  }

  return 'beacontrail.exe';
}

export class BeaconTrailClient {
  private child: ChildProcessWithoutNullStreams | null = null;
  private handshake: Promise<void> | null = null;
  private readonly pending = new Map<number, PendingRequest>();
  private buffer = '';
  private nextId = 1;

  constructor(private readonly executablePath: string = resolveBeaconTrailPath()) {}

  /** Call a tool and return its decoded JSON payload. */
  async callTool(name: string, args: Record<string, unknown> = {}, timeoutMs = DEFAULT_TIMEOUT_MS): Promise<unknown> {
    await this.start();

    const result = (await this.request('tools/call', { name, arguments: args }, timeoutMs)) as
      | JsonRpcResponse['result']
      | undefined;

    const text = result?.content?.[0]?.text ?? '';
    if (result?.isError) {
      throw new Error(text || `beacontrail tool ${name} failed`);
    }

    return text ? (JSON.parse(text) as unknown) : null;
  }

  /** Terminate the child process; safe to call repeatedly. */
  dispose(): void {
    for (const [, request] of this.pending) {
      clearTimeout(request.timer);
      request.reject(new Error('beacontrail client disposed'));
    }
    this.pending.clear();

    this.child?.kill();
    this.child = null;
    this.handshake = null;
  }

  private start(): Promise<void> {
    if (this.handshake) {
      return this.handshake;
    }

    this.handshake = (async () => {
      const child = spawn(this.executablePath, [], { windowsHide: true });
      this.child = child;

      child.stdout.setEncoding('utf8');
      child.stdout.on('data', (chunk: string) => this.consume(chunk));
      child.on('exit', (code) => this.failAll(new Error(`beacontrail exited with code ${code}`)));
      child.on('error', (error: Error) => this.failAll(error));

      await this.request('initialize', {
        protocolVersion: PROTOCOL_VERSION,
        capabilities: {},
        clientInfo: { name: 'beacontrail-electron', version: '0.1.0' }
      });

      this.send({ jsonrpc: '2.0', method: 'notifications/initialized' });
    })();

    // A failed handshake must not be cached, or every later call inherits it.
    this.handshake.catch(() => {
      this.handshake = null;
      this.child = null;
    });

    return this.handshake;
  }

  private request(method: string, params: unknown, timeoutMs = DEFAULT_TIMEOUT_MS): Promise<unknown> {
    const id = this.nextId++;

    return new Promise<unknown>((resolvePromise, rejectPromise) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        rejectPromise(new Error(`beacontrail ${method} timed out after ${timeoutMs}ms`));
      }, timeoutMs);

      this.pending.set(id, { resolve: resolvePromise, reject: rejectPromise, timer });
      this.send({ jsonrpc: '2.0', id, method, params });
    });
  }

  private send(message: unknown): void {
    this.child?.stdin.write(`${JSON.stringify(message)}\n`);
  }

  /** Split the stream on newlines; a chunk may hold part of a frame. */
  private consume(chunk: string): void {
    this.buffer += chunk;

    let newline = this.buffer.indexOf('\n');
    while (newline >= 0) {
      const line = this.buffer.slice(0, newline).trim();
      this.buffer = this.buffer.slice(newline + 1);
      newline = this.buffer.indexOf('\n');

      if (line) {
        this.dispatch(line);
      }
    }
  }

  private dispatch(line: string): void {
    let message: JsonRpcResponse;
    try {
      message = JSON.parse(line) as JsonRpcResponse;
    } catch {
      return; // Not a frame we can act on; the server never writes anything else.
    }

    if (typeof message.id !== 'number') {
      return;
    }

    const request = this.pending.get(message.id);
    if (!request) {
      return;
    }

    clearTimeout(request.timer);
    this.pending.delete(message.id);

    if (message.error) {
      request.reject(new Error(`beacontrail error ${message.error.code}: ${message.error.message}`));
      return;
    }

    request.resolve(message.result);
  }

  private failAll(error: Error): void {
    for (const [, request] of this.pending) {
      clearTimeout(request.timer);
      request.reject(error);
    }
    this.pending.clear();
    this.handshake = null;
    this.child = null;
  }
}

let shared: BeaconTrailClient | null = null;

/** Process-wide client, created on first use. */
export function getBeaconTrailClient(): BeaconTrailClient {
  shared ??= new BeaconTrailClient();
  return shared;
}
