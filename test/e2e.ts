// Black-box tests of a running package over HTTP (I-62b). No dependencies: `bun test/e2e.ts`.
//
//   bun test/e2e.ts --base http://127.0.0.1:6300                 # light: version, CORS, refusals
//   bun test/e2e.ts --base … --vectors DIR --heavy               # + abort, busy, every golden vector
//   bun test/e2e.ts --base … --vectors DIR --oom                 # a package started with too little memory
//
// DIR holds the AA 00062 P1 golden vectors (vectors.json, <vector>.request.bin, …). The heavy run needs
// about 12 GB for the package. Exit code 0 only when every check passes; results go to --out as JSON.

import { writeFileSync } from 'node:fs';

const argv = process.argv.slice(2);
const opt = (name: string) => {
  const i = argv.indexOf(`--${name}`);
  return i >= 0 ? argv[i + 1] : undefined;
};
const flag = (name: string) => argv.includes(`--${name}`);
const BASE = (opt('base') ?? 'http://127.0.0.1:6300').replace(/\/$/, '');
const VECTORS = opt('vectors');
const OUT = opt('out');
const ORIGIN = 'https://night-market.example';
const CIRCUITS = [
  'append_inbox_with_ed25519',
  'open_swap_shielded_with_ed25519',
  'withdraw_shielded_with_ed25519',
  'withdraw_unshielded_with_ed25519',
];
const KEY_SET = '21493588f30536e0f409dcf79deea54878f0c2cf6fee601a2359e54a776d5c5e';
const TAG = 'midnight:(proof-preimage-versioned,option(proving-data),option(fr-bls)):';
const PROOF_TAG = 'midnight:proof-versioned:';

const results: Array<{ name: string; ok: boolean; detail?: unknown }> = [];
const report: Record<string, unknown> = { base: BASE, startedAt: new Date().toISOString() };

function check(name: string, ok: boolean, detail?: unknown): boolean {
  results.push({ name, ok, ...(detail === undefined ? {} : { detail }) });
  console.log(`${ok ? 'PASS' : 'FAIL'} ${name}${detail === undefined ? '' : ` ${JSON.stringify(detail)}`}`);
  return ok;
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const b64 = (b: Uint8Array) => Buffer.from(b).toString('base64');

async function call(
  method: string,
  path: string,
  init: { body?: string; headers?: Record<string, string>; signal?: AbortSignal; timeoutMs?: number } = {},
) {
  // A stalled call is a failure, never a hang (proofs get 16 minutes, everything else 15 s).
  const timeout = AbortSignal.timeout(init.timeoutMs ?? 15_000);
  const res = await fetch(`${BASE}${path}`, {
    method,
    headers: { Origin: ORIGIN, ...(init.headers ?? {}) },
    body: init.body,
    signal: init.signal ? AbortSignal.any([init.signal, timeout]) : timeout,
    // @ts-expect-error Bun: no client-side timeout
    timeout: false,
  });
  const text = await res.text();
  let json: any;
  try {
    json = JSON.parse(text);
  } catch {
    json = undefined;
  }
  return { status: res.status, headers: res.headers, text, json };
}

const prove = (body: unknown, signal?: AbortSignal) =>
  call('POST', '/prove-circuit', { body: JSON.stringify(body), headers: { 'content-type': 'application/json' }, signal, timeoutMs: 960_000 });

function corsOk(h: Headers): boolean {
  return h.get('access-control-allow-origin') === ORIGIN && (h.get('vary') ?? '').includes('Origin') && h.get('access-control-allow-credentials') === null;
}

function errorIs(r: { status: number; json: any; headers: Headers }, status: number, code: string): boolean {
  return r.status === status && r.json?.error?.code === code && typeof r.json?.error?.message === 'string' && corsOk(r.headers);
}

/** A well-formed key-less request for `circuit` whose key location carries `vk`. */
function synthetic(circuit: string, vk: string) {
  const enc = new TextEncoder();
  const head = Buffer.concat([enc.encode(TAG), enc.encode(`\x02contract:${'cd'.repeat(32)}/${circuit}?vk=${vk}\x00tail`)]);
  const request = Buffer.concat([head, Uint8Array.of(0, 1), new Uint8Array(32).fill(9)]);
  return { circuit, proofRequest: b64(request), keyMaterialOffset: head.length };
}

async function waitIdle(ms: number): Promise<boolean> {
  const until = Date.now() + ms;
  while (Date.now() < until) {
    const v = await call('GET', '/version').catch(() => undefined);
    if (v?.status === 200 && v.json?.busy === false) return true;
    await sleep(250);
  }
  return false;
}

interface Vector {
  vector: string;
  circuit: string;
  keyMaterialOffset: number;
  request: { file: string; bytes: number };
  proof: { file: string; bytes: number; sha256: string; proveMs: number };
  reproof: { file: string; bytes: number; sha256: string; proveMs: number };
}

async function loadVectors(): Promise<Array<Vector & { body: unknown; requestBytes: Uint8Array }>> {
  if (!VECTORS) throw new Error('--vectors DIR is required for this mode');
  const meta = JSON.parse(await Bun.file(`${VECTORS}/vectors.json`).text());
  return Promise.all(
    (meta.vectors as Vector[]).map(async (v) => {
      const requestBytes = new Uint8Array(await Bun.file(`${VECTORS}/${v.request.file}`).arrayBuffer());
      return { ...v, requestBytes, body: { circuit: v.circuit, proofRequest: b64(requestBytes), keyMaterialOffset: v.keyMaterialOffset } };
    }),
  );
}

// ---------------------------------------------------------------- light
async function light(): Promise<string> {
  const v = await call('GET', '/version');
  const j = v.json ?? {};
  check('GET /version → 200 application/json', v.status === 200 && (v.headers.get('content-type') ?? '').startsWith('application/json'), v.status);
  check('version: api 1, proofServer 9.0.0-rc.8, the key set', j.api === 1 && j.proofServer === '9.0.0-rc.8' && j.keySet === KEY_SET, {
    api: j.api,
    proofServer: j.proofServer,
    keySet: j.keySet,
  });
  check('version: the four circuits, sorted', JSON.stringify(j.circuits) === JSON.stringify(CIRCUITS), j.circuits);
  check('version: package, busy, machine', typeof j.package === 'string' && j.package.length > 0 && typeof j.busy === 'boolean' &&
    Number.isInteger(j.machine?.cpus) && (j.machine?.memoryBytes === null || Number.isInteger(j.machine?.memoryBytes)), {
    package: j.package,
    busy: j.busy,
    machine: j.machine,
  });
  check('version: exactly the I-62b fields', JSON.stringify(Object.keys(j).sort()) === JSON.stringify(['api', 'busy', 'circuits', 'keySet', 'machine', 'package', 'proofServer']), Object.keys(j));
  check('CORS on GET: Origin echoed, Vary: Origin, no credentials', corsOk(v.headers), {
    acao: v.headers.get('access-control-allow-origin'),
    vary: v.headers.get('vary'),
    acac: v.headers.get('access-control-allow-credentials'),
  });
  report.version = j;

  for (const path of ['/prove-circuit', '/version', '/anything']) {
    const p = await call('OPTIONS', path, {
      headers: {
        'Access-Control-Request-Method': 'POST',
        'Access-Control-Request-Headers': 'content-type',
        'Access-Control-Request-Private-Network': 'true',
      },
    });
    const h = p.headers;
    const ok =
      p.status === 204 &&
      corsOk(h) &&
      h.get('access-control-allow-methods') === 'GET, POST, OPTIONS' &&
      h.get('access-control-allow-headers') === 'content-type' &&
      h.get('access-control-max-age') === '600' &&
      h.get('access-control-allow-private-network') === 'true';
    check(`OPTIONS ${path} preflight → 204 with Allow-Private-Network: true`, ok, Object.fromEntries([...h.entries()].filter(([k]) => k.startsWith('access-control') || k === 'vary')));
  }

  const noOrigin = await fetch(`${BASE}/version`);
  check('no Origin → no Access-Control-Allow-Origin', noOrigin.headers.get('access-control-allow-origin') === null && (await noOrigin.text()).length > 0);

  const vk = 'ab'.repeat(32);
  let r = await prove({ circuit: 'register_device_with_ed25519', proofRequest: 'AAAA', keyMaterialOffset: 1 });
  check('unknown circuit → 404 unknown-circuit', errorIs(r, 404, 'unknown-circuit'), r.json);
  r = await call('POST', '/prove-circuit', { body: '{not json', headers: { 'content-type': 'application/json' } });
  check('not JSON → 400 bad-request', errorIs(r, 400, 'bad-request'), r.json);
  r = await call('POST', '/prove-circuit', { body: JSON.stringify(synthetic(CIRCUITS[1]!, vk)), headers: { 'content-type': 'text/plain' } });
  check('content-type not application/json → 400 bad-request', errorIs(r, 400, 'bad-request'), r.json);
  r = await call('POST', '/prove-circuit', { body: 'x'.repeat(256 * 1024 + 1), headers: { 'content-type': 'application/json' } });
  check('a body over 256 KiB → 413 too-large', errorIs(r, 413, 'too-large'), r.json);
  r = await call('GET', '/version');
  check('the connection is still usable after a 413 (the body was drained)', r.status === 200, r.status);
  r = await call('POST', '/prove-circuit', { body: 'x'.repeat(2 * 1024 * 1024), headers: { 'content-type': 'application/json' } });
  check('a 2 MiB body → 413 too-large', errorIs(r, 413, 'too-large'), r.json);
  r = await call('POST', '/nope', { body: 'y'.repeat(512 * 1024), headers: { 'content-type': 'application/json' } });
  check('an unknown route with a 512 KiB body → 404 not-found', errorIs(r, 404, 'not-found'), r.json);
  r = await call('GET', '/version');
  check('the connection is still usable after unread bodies', r.status === 200, r.status);
  const badTag = synthetic(CIRCUITS[1]!, vk);
  badTag.proofRequest = b64(Buffer.concat([Buffer.from('X'), Buffer.from(badTag.proofRequest, 'base64').subarray(1)]));
  r = await prove(badTag);
  check('a request without the /prove tag → 400 bad-request', errorIs(r, 400, 'bad-request'), r.json);
  const badOffset = synthetic(CIRCUITS[1]!, vk);
  badOffset.keyMaterialOffset -= 1;
  r = await prove(badOffset);
  check('a keyMaterialOffset not on the 0x00 → 400 bad-request', errorIs(r, 400, 'bad-request'), r.json);
  r = await prove(synthetic(CIRCUITS[1]!, vk));
  check('a key location with another verifier key → 422 wrong-key', errorIs(r, 422, 'wrong-key'), r.json);
  r = await call('GET', '/nope');
  check('an unknown route → 404 not-found', errorIs(r, 404, 'not-found'), r.json);
  r = await call('GET', '/prove-circuit');
  check('GET /prove-circuit → 405', r.status === 405 && corsOk(r.headers), r.json);
  return j.package;
}

// ---------------------------------------------------------------- heavy
async function heavy(): Promise<void> {
  const vectors = await loadVectors();
  const maker = vectors.find((v) => v.vector.endsWith('.maker')) ?? vectors[0]!;

  // A golden request asked as another circuit, and with its vk altered: both 422 before any proving.
  const other = vectors.find((v) => v.circuit !== maker.circuit);
  if (other) {
    const r = await prove({ ...(maker.body as object), circuit: other.circuit });
    check(`golden ${maker.vector} asked as ${other.circuit} → 422 wrong-key`, errorIs(r, 422, 'wrong-key'), r.json);
  }
  const altered = Buffer.from(maker.requestBytes);
  const at = altered.indexOf(Buffer.from('?vk=')) + 4;
  altered[at] = altered[at] === 0x30 ? 0x31 : 0x30;
  let r = await prove({ ...(maker.body as object), proofRequest: b64(altered) });
  check(`golden ${maker.vector} with its vk altered → 422 wrong-key`, errorIs(r, 422, 'wrong-key'), r.json);

  // A client that goes away mid-proof: the slot frees and rc.8 restarts (the next proofs prove it works).
  const ac = new AbortController();
  const aborted = prove(maker.body, ac.signal).catch((e) => ({ status: -1, error: String(e) }));
  await sleep(4000);
  const busyMid = await call('GET', '/version');
  ac.abort();
  await aborted;
  const idle = await waitIdle(15_000);
  check('client abort mid-proof → busy, then the slot frees', busyMid.json?.busy === true && idle, { busyMid: busyMid.json?.busy, idleAfterAbort: idle });

  const proofs: Record<string, unknown>[] = [];
  for (const [i, v] of vectors.entries()) {
    const t0 = performance.now();
    const pending = prove(v.body);
    if (i === 0) {
      // While it proves: busy is true and a second request gets 429.
      await sleep(3000);
      const ver = await call('GET', '/version');
      check('while proving: /version busy = true', ver.json?.busy === true, ver.json?.busy);
      const second = await prove(v.body);
      check('a second request while busy → 429 busy, Retry-After: 30', errorIs(second, 429, 'busy') && second.headers.get('retry-after') === '30', {
        status: second.status,
        code: second.json?.error?.code,
        retryAfter: second.headers.get('retry-after'),
      });
    }
    const res = await pending;
    const wallMs = Math.round(performance.now() - t0);
    const proof = res.json?.proof ? Buffer.from(res.json.proof, 'base64') : Buffer.alloc(0);
    const head = proof.subarray(0, PROOF_TAG.length).toString('latin1');
    const sha = new Bun.CryptoHasher('sha256').update(proof).digest('hex');
    const ok = res.status === 200 && proof.length === 8028 && head === PROOF_TAG && Number.isInteger(res.json?.proveMs) && corsOk(res.headers);
    check(`golden ${v.vector} → 200, an 8,028-byte proof`, ok, {
      status: res.status,
      bytes: proof.length,
      head,
      proveMs: res.json?.proveMs,
      wallMs,
      ...(res.status !== 200 ? { error: res.json?.error } : {}),
    });
    check(`golden ${v.vector}: same size as the P1 proofs, fresh randomness`, proof.length === v.proof.bytes && proof.length === v.reproof.bytes && sha !== v.proof.sha256 && sha !== v.reproof.sha256);
    proofs.push({
      vector: v.vector,
      circuit: v.circuit,
      status: res.status,
      bytes: proof.length,
      sha256: sha,
      proveMs: res.json?.proveMs,
      wallMs,
      p1: { relayProveMs: v.proof.proveMs, reproofMs: v.reproof.proveMs, bytes: v.reproof.bytes },
    });
    if (VECTORS && OUT && proof.length) writeFileSync(OUT.replace(/\.json$/, `.${v.vector}.proof.bin`), proof);
    check(`after ${v.vector}: /version busy = false`, await waitIdle(30_000));
  }
  report.proofs = proofs;
}

// ---------------------------------------------------------------- oom
async function oom(): Promise<void> {
  const [v] = await loadVectors();
  const outcomes: unknown[] = [];
  for (let i = 0; i < 2; i++) {
    const r = await prove(v!.body);
    outcomes.push({ status: r.status, code: r.json?.error?.code, message: r.json?.error?.message });
    check(`attempt ${i + 1} in too little memory → 503 out-of-memory`, errorIs(r, 503, 'out-of-memory'), r.json);
    const ver = await call('GET', '/version');
    check(`attempt ${i + 1}: the front still answers /version, not busy`, ver.status === 200 && ver.json?.busy === false);
    await sleep(3000);
  }
  report.oom = outcomes;
}

let failed = false;
try {
  await light();
  if (flag('heavy')) await heavy();
  if (flag('oom')) await oom();
} catch (e) {
  check('the run itself', false, String(e));
}
failed = results.some((r) => !r.ok);
report.finishedAt = new Date().toISOString();
report.results = results;
report.passed = results.filter((r) => r.ok).length;
report.failed = results.filter((r) => !r.ok).length;
if (OUT) writeFileSync(OUT, JSON.stringify(report, null, 1));
console.log(`${report.passed} passed, ${report.failed} failed`);
process.exit(failed ? 1 : 0);
