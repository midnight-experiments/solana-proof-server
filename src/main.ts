// The Night Market prover package's front (AA 00062, interface I-62b).
//
//   GET  /version        what this package proves: rc.8's version, the key set, the four circuits
//   POST /prove-circuit  {circuit, proofRequest, keyMaterialOffset} → {proof, proveMs}
//   OPTIONS *            the CORS preflight, with Access-Control-Allow-Private-Network: true
//
// It listens on 0.0.0.0:6300 INSIDE the container; users publish it with -p 127.0.0.1:6300:6300.
// rc.8 runs as a child on an internal port (see prover.ts).

import { API_VERSION, CIRCUITS, KEY_SET, LIMITS, PROOF_SERVER_VERSION, loadSettings } from './config.ts';
import { type KeyBundle, loadKeyBundle } from './keys.ts';
import { log } from './log.ts';
import { machine } from './machine.ts';
import { ClientGone, ProofServer } from './prover.ts';
import { ApiError, checkKeyLocation, concat, encodeBase64, parseProveRequest } from './splice.ts';

const settings = loadSettings();
let keys: KeyBundle;
try {
  keys = loadKeyBundle(settings.keysDir);
} catch (e) {
  log('fatal', { reason: e instanceof Error ? e.message : String(e) });
  process.exit(1);
}
log('keys-ok', { keySet: KEY_SET, circuits: CIRCUITS.join(',') });

const rc8 = new ProofServer(settings);
rc8.start();

/** One proof at a time: true from the moment a proof is accepted until rc.8 has answered. */
let busy = false;

const PREFLIGHT = {
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'content-type',
  'Access-Control-Max-Age': '600',
  'Access-Control-Allow-Private-Network': 'true',
};

/** CORS on every response: echo the Origin (no credentials). */
function headersFor(req: Request, extra: Record<string, string> = {}): Headers {
  const headers = new Headers({ 'Cache-Control': 'no-store', ...extra });
  const origin = req.headers.get('origin');
  if (origin) headers.set('Access-Control-Allow-Origin', origin);
  headers.set('Vary', 'Origin');
  return headers;
}

function json(req: Request, status: number, value: unknown, extra: Record<string, string> = {}): Response {
  const body = JSON.stringify(value);
  const headers = headersFor(req, { 'Content-Type': 'application/json', ...extra });
  headers.set('Content-Length', String(Buffer.byteLength(body)));
  return new Response(body, { status, headers });
}

function errorResponse(req: Request, e: ApiError): Response {
  return json(req, e.status, { error: { code: e.code, message: e.message } }, e.headers);
}

/**
 * The whole body, read to its end even when it is too large or about to be refused: a request whose
 * body is left unread leaves its keep-alive connection out of step, and the client's NEXT request on
 * it stalls. Bun's own cap (maxRequestBodySize) bounds what is read; at most LIMITS.bodyBytes is kept.
 */
async function readBody(req: Request): Promise<{ bytes: Uint8Array; total: number }> {
  if (!req.body || req.bodyUsed) return { bytes: new Uint8Array(), total: 0 };
  const chunks: Uint8Array[] = [];
  let total = 0;
  for await (const chunk of req.body as unknown as AsyncIterable<Uint8Array>) {
    total += chunk.length;
    if (total <= LIMITS.bodyBytes) chunks.push(chunk);
  }
  return { bytes: total <= LIMITS.bodyBytes ? concat(chunks) : new Uint8Array(), total };
}

interface Ctx {
  reqBytes: number;
  extra: Record<string, number | string | undefined>;
}

async function proveCircuit(req: Request, ctx: Ctx): Promise<Response> {
  const { bytes: raw, total } = await readBody(req);
  ctx.reqBytes = total;
  if (total > LIMITS.bodyBytes) throw new ApiError(413, 'too-large', `the body is over ${LIMITS.bodyBytes} bytes`);
  const contentType = req.headers.get('content-type') ?? '';
  if (!/^application\/json(\s*;|$)/i.test(contentType)) {
    throw new ApiError(400, 'bad-request', 'content-type must be application/json');
  }
  let body: unknown;
  try {
    body = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(raw));
  } catch {
    throw new ApiError(400, 'bad-request', 'the body is not JSON');
  }
  const request = parseProveRequest(body);
  const circuitKeys = keys.get(request.circuit)!;
  checkKeyLocation(request, circuitKeys.verifierSha256);
  if (busy) throw new ApiError(429, 'busy', 'this prover runs one proof at a time and one is running', { 'Retry-After': '30' });
  busy = true;
  let reachedProofServer = false;
  try {
    if (!(await rc8.waitReady(settings.startWaitMs))) {
      throw new ApiError(503, 'starting', 'the proof server is starting; try again in a few seconds');
    }
    reachedProofServer = true;
    const result = await rc8.prove(request, circuitKeys, req.signal);
    ctx.extra.proveMs = result.proveMs;
    ctx.extra.rc8PeakRssMiB = result.peakRssBytes === null ? undefined : Math.round(result.peakRssBytes / 2 ** 20);
    return json(req, 200, { proof: encodeBase64(result.proof), proveMs: result.proveMs });
  } finally {
    // A fresh rc.8 after every proof, whatever the outcome: it keeps memory between proofs.
    if (reachedProofServer) rc8.recycle();
    busy = false;
  }
}

function version(req: Request): Response {
  return json(req, 200, {
    api: API_VERSION,
    package: settings.packageVersion,
    proofServer: PROOF_SERVER_VERSION,
    keySet: KEY_SET,
    circuits: [...CIRCUITS],
    busy,
    machine: machine(),
  });
}

const ROUTES: Record<string, string> = { '/version': 'GET', '/prove-circuit': 'POST' };
const HEALTHCHECK_AGENT = 'solana-proof-server-healthcheck';

/** The bit of Bun's server the routes use. */
interface IdleTimeouts {
  timeout(req: Request, seconds: number): void;
}

async function route(req: Request, server: IdleTimeouts, path: string, ctx: Ctx): Promise<Response> {
  if (req.method === 'OPTIONS') {
    const headers = headersFor(req, PREFLIGHT);
    headers.set('Content-Length', '0');
    return new Response(null, { status: 204, headers });
  }
  const method = ROUTES[path];
  if (method === undefined) throw new ApiError(404, 'not-found', 'no such route; see GET /version and POST /prove-circuit');
  if (req.method !== method) {
    throw new ApiError(405, 'method-not-allowed', `${path} takes ${method}`, { Allow: `${method}, OPTIONS` });
  }
  if (path === '/version') return version(req);
  // A proof sends nothing for tens of seconds: no idle timeout on this request.
  server.timeout(req, 0);
  return proveCircuit(req, ctx);
}

const server = Bun.serve({
  hostname: '0.0.0.0',
  port: settings.port,
  // Our own limit (256 KiB, answered 413 with CORS) is checked first; this is Bun's hard stop.
  maxRequestBodySize: 4 * 1024 * 1024,
  idleTimeout: 30,
  async fetch(req, srv) {
    const t0 = performance.now();
    const path = new URL(req.url).pathname;
    const ctx: Ctx = { reqBytes: 0, extra: {} };
    let res: Response;
    try {
      res = await route(req, srv, path, ctx);
    } catch (e) {
      if (e instanceof ClientGone) {
        log('request', { method: req.method, path: path.slice(0, 100), status: 499, reqBytes: ctx.reqBytes, ms: Math.round(performance.now() - t0), note: 'client closed the request; rc.8 restarted' });
        return new Response(null, { status: 499 });
      }
      if (!(e instanceof ApiError)) log('internal-error', { reason: e instanceof Error ? e.message : String(e) });
      res = errorResponse(req, e instanceof ApiError ? e : new ApiError(500, 'internal', 'internal error'));
    }
    // Any body a route did not read is drained, so the connection stays usable (see readBody).
    if (req.body && !req.bodyUsed) ctx.reqBytes ||= (await readBody(req).catch(() => ({ total: 0 }))).total;
    // The image's own health check (every 30 s) is not worth a line.
    if (res.status === 200 && req.headers.get('user-agent') === HEALTHCHECK_AGENT) return res;
    log('request', {
      method: req.method,
      path: path.slice(0, 100),
      status: res.status,
      reqBytes: ctx.reqBytes,
      resBytes: Number(res.headers.get('content-length') ?? 0),
      ms: Math.round(performance.now() - t0),
      ...ctx.extra,
    });
    return res;
  },
  error(e) {
    log('internal-error', { reason: e.message });
    return new Response(JSON.stringify({ error: { code: 'internal', message: 'internal error' } }), {
      status: 500,
      headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', Vary: 'Origin' },
    });
  },
});
log('listening', { port: server.port, package: settings.packageVersion, proofServer: PROOF_SERVER_VERSION });

for (const signal of ['SIGTERM', 'SIGINT'] as const) {
  process.on(signal, () => {
    log('shutdown', { signal });
    void server.stop(true);
    void rc8.shutdown().then(() => process.exit(0));
  });
}
