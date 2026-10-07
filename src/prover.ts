// rc.8 as a supervised child of the front.
//
// - It runs with one worker and a job capacity of one: one k = 18 proof needs about 9.4 GiB, two at
//   once about 19 GiB (rc.8's default is two workers).
// - It is RESTARTED after every proof: rc.8 keeps memory between proofs (3.9 → 7.1 GiB resident over
//   three proofs in AA 00062 P1), so a fresh process per proof keeps the user's memory flat.
// - It is restarted after any unexpected exit. The kernel's OOM killer picks the biggest process, and
//   the child also raises its own oom_score_adj to 1000 so that the front is never the one killed.
// - Its KZG params are baked into the image (MIDNIGHT_PP) and it runs with --no-fetch-params, so it
//   needs no network at all.

import { readFileSync } from 'node:fs';
import { open } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import type { Subprocess } from 'bun';
import { LIMITS, PROOF_TAG, PROOF_SERVER_VERSION, type Settings } from './config.ts';
import type { CircuitKeys } from './keys.ts';
import { ApiError, type ProveRequest, spliceParts, startsWith } from './splice.ts';
import { log } from './log.ts';

type State = 'stopped' | 'starting' | 'ready';

/** The client went away before the proof finished: nothing to answer. */
export class ClientGone extends Error {}

export interface ProofResult {
  proof: Uint8Array;
  proveMs: number;
  /** rc.8's peak resident memory (VmHWM) for this proof, when /proc tells. */
  peakRssBytes: number | null;
}

const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));
const PROOF_TAG_BYTES = new TextEncoder().encode(PROOF_TAG);
const ANSI = /\x1b\[[0-9;]*m/g;

export class ProofServer {
  private proc: Subprocess<'ignore', 'pipe', 'pipe'> | undefined;
  private state: State = 'stopped';
  private readonly retired = new WeakSet<Subprocess>();
  private waiters: Array<() => void> = [];
  private backoffMs = 500;
  private shuttingDown = false;
  private versionChecked = false;
  /** How many times rc.8 has been started. */
  starts = 0;

  constructor(private readonly settings: Settings) {}

  get pid(): number | undefined {
    return this.proc?.pid;
  }

  get ready(): boolean {
    return this.state === 'ready';
  }

  private url(path: string): string {
    return `http://127.0.0.1:${this.settings.proofServerPort}${path}`;
  }

  /** Starts rc.8 (no-op while one is starting or ready). */
  start(): void {
    if (this.shuttingDown || this.state !== 'stopped') return;
    const s = this.settings;
    const args = [
      '--port', String(s.proofServerPort),
      '--num-workers', '1',
      '--job-capacity', '1',
      '--job-timeout', String(s.proofServerJobTimeoutSeconds),
      '--no-fetch-params',
    ];
    // `sh` raises the child's own OOM score (allowed unprivileged), then becomes rc.8 (same pid).
    const proc = Bun.spawn(['sh', '-c', 'echo 1000 > /proc/self/oom_score_adj; exec "$0" "$@"', s.proofServerBin, ...args], {
      stdin: 'ignore',
      stdout: 'pipe',
      stderr: 'pipe',
      env: { PATH: '/usr/local/bin:/usr/bin:/bin', MIDNIGHT_PP: s.paramsDir, HOME: process.env.HOME ?? '/tmp' },
    });
    this.proc = proc;
    this.state = 'starting';
    this.starts += 1;
    const startedAt = Date.now();
    log('rc8-start', { pid: proc.pid, start: this.starts });
    void forwardLines(proc.stdout);
    void forwardLines(proc.stderr);
    void proc.exited.then(() => this.onExit(proc));
    void this.awaitHealthy(proc, startedAt);
  }

  private async awaitHealthy(proc: Subprocess, startedAt: number): Promise<void> {
    while (this.proc === proc && this.state === 'starting') {
      try {
        const r = await fetch(this.url('/health'), { signal: AbortSignal.timeout(1000) });
        if (r.ok) {
          await r.arrayBuffer();
          if (!this.versionChecked) {
            const v = (await (await fetch(this.url('/version'))).text()).trim();
            if (v !== PROOF_SERVER_VERSION) {
              log('fatal', { reason: `rc.8 reports version ${JSON.stringify(v)}, the package pins ${PROOF_SERVER_VERSION}` });
              process.exit(1);
            }
            this.versionChecked = true;
          }
          if (this.proc !== proc) return;
          this.state = 'ready';
          this.backoffMs = 500;
          log('rc8-ready', { pid: proc.pid, startMs: Date.now() - startedAt });
          const w = this.waiters;
          this.waiters = [];
          for (const f of w) f();
          return;
        }
      } catch {
        // not listening yet
      }
      await sleep(100);
    }
  }

  private onExit(proc: Subprocess): void {
    const expected = this.retired.has(proc) || this.shuttingDown;
    log('rc8-exit', {
      pid: proc.pid,
      code: proc.exitCode,
      signal: proc.signalCode,
      expected,
      ...(expected ? {} : { note: proc.signalCode === 'SIGKILL' ? 'killed: most likely out of memory' : 'unexpected' }),
    });
    if (this.proc !== proc) return;
    this.proc = undefined;
    this.state = 'stopped';
    if (expected || this.shuttingDown) return;
    const delay = this.backoffMs;
    this.backoffMs = Math.min(this.backoffMs * 2, 30_000);
    setTimeout(() => this.start(), delay);
  }

  /** Waits until rc.8 answers its health check, up to `ms`. */
  async waitReady(ms: number): Promise<boolean> {
    if (this.state === 'ready') return true;
    if (this.state === 'stopped') this.start();
    let done!: () => void;
    const ready = new Promise<void>((r) => (done = r));
    this.waiters.push(done);
    const timer = sleep(ms).then(() => 'timeout' as const);
    const outcome = await Promise.race([ready.then(() => 'ready' as const), timer]);
    return outcome === 'ready';
  }

  /** Kills the current rc.8 (its memory goes with it) and starts a fresh one. */
  recycle(): void {
    const proc = this.proc;
    if (!proc) {
      this.start();
      return;
    }
    this.retired.add(proc);
    this.proc = undefined;
    // Requests arriving now wait for the new process; it starts once the old one has released its port.
    this.state = 'starting';
    proc.kill('SIGKILL');
    void proc.exited.then(() => {
      if (this.proc !== undefined || this.state !== 'starting') return;
      this.state = 'stopped';
      this.start();
    });
  }

  /**
   * Stops rc.8 at once. It holds nothing worth a graceful stop (a proof in flight is lost either way),
   * and its own graceful shutdown waits about 3 s for idle connections, long enough for `docker stop`
   * to escalate to SIGKILL on some hosts.
   */
  async shutdown(): Promise<void> {
    this.shuttingDown = true;
    const proc = this.proc;
    if (!proc) return;
    proc.kill('SIGKILL');
    await Promise.race([proc.exited, sleep(2000)]);
  }

  /** rc.8's peak resident memory so far (VmHWM), in bytes. */
  peakRssBytes(): number | null {
    const pid = this.proc?.pid;
    if (!pid) return null;
    try {
      const m = /^VmHWM:\s+(\d+) kB$/m.exec(readFileSync(`/proc/${pid}/status`, 'utf8'));
      return m ? Number(m[1]) * 1024 : null;
    } catch {
      return null;
    }
  }

  /**
   * One proof: streams R[0..o] | 0x01 | len pk | pk | len vk | vk | len ir | ir | R[o+1..] to rc.8's
   * /prove. The prover key's SHA-256 is checked as it is read, before the rest of the body is sent.
   * The caller recycles rc.8 afterwards, whatever the outcome.
   */
  async prove(req: ProveRequest, keys: CircuitKeys, clientSignal: AbortSignal): Promise<ProofResult> {
    const proc = this.proc;
    if (!proc || this.state !== 'ready') throw new ApiError(503, 'starting', 'the proof server is starting; try again in a few seconds');
    const parts = spliceParts(req, keys.proverBytes, keys.verifierKey, keys.ir);
    let keyFailure: string | null = null;
    const body = keyStream(keys, parts.prefix, parts.suffix, this.settings.keyChunkBytes, (m) => (keyFailure = m));
    const timeout = AbortSignal.timeout(this.settings.proofTimeoutMs);
    const signal = AbortSignal.any([timeout, clientSignal]);
    const t0 = performance.now();
    let response: Response;
    try {
      response = await fetch(this.url('/prove'), {
        method: 'POST',
        body,
        headers: { 'content-type': 'application/octet-stream', 'content-length': String(parts.total) },
        signal,
        // @ts-expect-error Bun: streamed request body
        duplex: 'half',
        // Bun: no client-side timeout of its own; `signal` bounds the call.
        timeout: false,
      });
    } catch (e) {
      throw await this.classifyFailure(proc, e, timeout, clientSignal, keyFailure);
    }
    let bytes: Uint8Array;
    try {
      bytes = new Uint8Array(await response.arrayBuffer());
    } catch (e) {
      throw await this.classifyFailure(proc, e, timeout, clientSignal, keyFailure);
    }
    const proveMs = Math.round(performance.now() - t0);
    const peakRssBytes = this.peakRssBytes();
    if (response.status === 200) {
      if (bytes.length > LIMITS.proofBytes || !startsWith(bytes, PROOF_TAG_BYTES)) {
        throw new ApiError(502, 'prover-error', `the proof server answered 200 without a proof (${bytes.length} bytes)`);
      }
      return { proof: bytes, proveMs, peakRssBytes };
    }
    const text = new TextDecoder().decode(bytes.subarray(0, 4 * LIMITS.errorTextChars)).slice(0, LIMITS.errorTextChars);
    if (response.status === 429) throw new ApiError(429, 'busy', 'the proof server is busy', { 'Retry-After': '30' });
    throw new ApiError(502, 'prover-error', text || `the proof server answered ${response.status}`);
  }

  private async classifyFailure(
    proc: Subprocess,
    e: unknown,
    timeout: AbortSignal,
    clientSignal: AbortSignal,
    keyFailure: string | null,
  ): Promise<Error> {
    if (keyFailure) return new ApiError(502, 'prover-error', keyFailure);
    if (clientSignal.aborted) return new ClientGone('the client closed the request');
    if (timeout.aborted) {
      return new ApiError(504, 'timeout', `no proof after ${Math.round(this.settings.proofTimeoutMs / 1000)} s`);
    }
    // A dropped connection: did rc.8 die (the OOM killer) or is it still there?
    const died = await Promise.race([proc.exited.then(() => true), sleep(2000).then(() => false)]);
    if (died) {
      return new ApiError(
        503,
        'out-of-memory',
        `the proof server stopped during the proof (${proc.signalCode ?? `exit ${proc.exitCode}`}), most likely out of memory: ` +
          'one proof needs about 12 GB. It is restarting.',
      );
    }
    const why = e instanceof Error ? e.message : String(e);
    return new ApiError(502, 'prover-error', `the connection to the proof server failed: ${why}`.slice(0, LIMITS.errorTextChars));
  }
}

/** prefix | the prover key file (SHA-256 checked as it is read) | suffix. */
function keyStream(
  keys: CircuitKeys,
  prefix: Uint8Array,
  suffix: Uint8Array,
  chunkBytes: number,
  onKeyFailure: (message: string) => void,
): ReadableStream<Uint8Array> {
  let file: Awaited<ReturnType<typeof open>> | undefined;
  let sent = -1;
  const hash = createHash('sha256');
  const close = async () => {
    const f = file;
    file = undefined;
    await f?.close().catch(() => undefined);
  };
  return new ReadableStream<Uint8Array>({
    async pull(controller) {
      try {
        if (sent === -1) {
          file = await open(keys.proverPath, 'r');
          sent = 0;
          controller.enqueue(prefix);
          return;
        }
        if (sent < keys.proverBytes) {
          const chunk = new Uint8Array(Math.min(chunkBytes, keys.proverBytes - sent));
          const { bytesRead } = await file!.read(chunk, 0, chunk.length, sent);
          if (bytesRead === 0) throw new Error(`${keys.circuit}.prover is shorter than ${keys.proverBytes} bytes`);
          const piece = bytesRead === chunk.length ? chunk : chunk.subarray(0, bytesRead);
          hash.update(piece);
          sent += bytesRead;
          controller.enqueue(piece);
          return;
        }
        await close();
        const actual = hash.digest('hex');
        if (actual !== keys.proverSha256) {
          throw new Error(`the bundled ${keys.circuit}.prover failed its SHA-256 check (${actual}); the image is damaged`);
        }
        controller.enqueue(suffix);
        controller.close();
      } catch (e) {
        await close();
        const message = e instanceof Error ? e.message : String(e);
        onKeyFailure(message);
        log('key-error', { circuit: keys.circuit, reason: message });
        controller.error(e);
      }
    },
    async cancel() {
      await close();
    },
  });
}

/** rc.8's own log lines, colour codes stripped and cut to 300 characters (rc.8 runs at INFO: no bodies). */
async function forwardLines(stream: ReadableStream<Uint8Array>): Promise<void> {
  const decoder = new TextDecoder();
  let buffered = '';
  try {
    for await (const chunk of stream) {
      buffered += decoder.decode(chunk, { stream: true });
      let nl: number;
      while ((nl = buffered.indexOf('\n')) >= 0) {
        const line = buffered.slice(0, nl).replace(ANSI, '').trimEnd();
        buffered = buffered.slice(nl + 1);
        if (line) process.stdout.write(`rc8 | ${line.slice(0, 300)}\n`);
      }
      if (buffered.length > 4096) buffered = buffered.slice(-4096);
    }
  } catch {
    // the child is gone
  }
}
