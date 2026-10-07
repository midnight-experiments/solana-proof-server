// I-62b's request rules and splice, as pure functions (no I/O): unit-tested in test/splice.test.ts.
//
// A request carries the ledger's key-less /prove body R = HEAD | 0x00 | TAIL, and o = keyMaterialOffset
// (the index of that 0x00, the `None` of the key material). The package sends rc.8
//
//   R[0..o] | 0x01 | compact(len pk) | pk | compact(len vk) | vk | compact(len ir) | ir | R[o+1..]
//
// where pk, vk and ir are the circuit's bundled prover key, verifier key and binary ZKIR. On the three
// P1 golden vectors this was byte-identical to the Night Market relay's own body.

import { CIRCUITS, type Circuit, LIMITS, PROVE_TAG } from './config.ts';

/** An answer the front gives instead of a proof: `{"error": {code, message}}` with this status. */
export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
    readonly headers: Record<string, string> = {},
  ) {
    super(message);
  }
}

export interface ProveRequest {
  circuit: Circuit;
  /** The key-less /prove body R. */
  request: Uint8Array;
  /** o: R[o] = 0x00 is the key material's `None`. */
  offset: number;
}

const encoder = new TextEncoder();
const TAG_BYTES = encoder.encode(PROVE_TAG);
const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

export function isCircuit(value: unknown): value is Circuit {
  return typeof value === 'string' && (CIRCUITS as readonly string[]).includes(value);
}

/** Standard base64 with padding (RFC 4648 §4), strictly. */
export function decodeBase64(text: string): Uint8Array | undefined {
  if (text.length % 4 !== 0 || !BASE64.test(text)) return undefined;
  return new Uint8Array(Buffer.from(text, 'base64'));
}

export function encodeBase64(bytes: Uint8Array): string {
  return Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength).toString('base64');
}

/**
 * Checks a parsed POST /prove-circuit body, in I-62b's order: the circuit (404 `unknown-circuit`),
 * then the shape and the splice rules (400 `bad-request`; 413 `too-large` for an oversized request).
 * The key-location check (422) needs the bundled verifier key's hash: see checkKeyLocation.
 */
export function parseProveRequest(body: unknown): ProveRequest {
  if (typeof body !== 'object' || body === null || Array.isArray(body)) {
    throw new ApiError(400, 'bad-request', 'the body must be a JSON object {circuit, proofRequest, keyMaterialOffset}');
  }
  const { circuit, proofRequest, keyMaterialOffset } = body as Record<string, unknown>;
  if (typeof circuit !== 'string') throw new ApiError(400, 'bad-request', '`circuit` must be a string');
  if (!isCircuit(circuit)) {
    throw new ApiError(404, 'unknown-circuit', `this package does not prove that circuit; it proves ${CIRCUITS.join(', ')}`);
  }
  if (typeof proofRequest !== 'string') throw new ApiError(400, 'bad-request', '`proofRequest` must be a base64 string');
  // A cheap bound before decoding: 4 base64 characters per 3 bytes.
  if (proofRequest.length > Math.ceil(LIMITS.proofRequestBytes / 3) * 4) {
    throw new ApiError(413, 'too-large', `\`proofRequest\` is over ${LIMITS.proofRequestBytes} bytes`);
  }
  const request = decodeBase64(proofRequest);
  if (request === undefined) throw new ApiError(400, 'bad-request', '`proofRequest` is not standard padded base64');
  if (request.length > LIMITS.proofRequestBytes) {
    throw new ApiError(413, 'too-large', `\`proofRequest\` is over ${LIMITS.proofRequestBytes} bytes`);
  }
  if (typeof keyMaterialOffset !== 'number' || !Number.isSafeInteger(keyMaterialOffset)) {
    throw new ApiError(400, 'bad-request', '`keyMaterialOffset` must be an integer');
  }
  checkSpliceRules(request, keyMaterialOffset);
  return { circuit, request, offset: keyMaterialOffset };
}

/** The splice rules: the tag, R[o] = 0x00, and a tail R[o+1..] of `00` or `01` + 32 bytes. */
export function checkSpliceRules(request: Uint8Array, offset: number): void {
  if (request.length < TAG_BYTES.length || !startsWith(request, TAG_BYTES)) {
    throw new ApiError(400, 'bad-request', '`proofRequest` does not start with the key-less /prove tag');
  }
  if (offset <= TAG_BYTES.length || offset >= request.length - 1) {
    throw new ApiError(400, 'bad-request', '`keyMaterialOffset` is outside the request');
  }
  if (request[offset] !== 0x00) {
    throw new ApiError(400, 'bad-request', 'the byte at `keyMaterialOffset` is not 0x00 (no key material)');
  }
  const tail = request.length - offset - 1;
  const tailOk = (request[offset + 1] === 0x00 && tail === 1) || (request[offset + 1] === 0x01 && tail === 33);
  if (!tailOk) {
    throw new ApiError(400, 'bad-request', 'the bytes after `keyMaterialOffset` are not `00` or `01` + 32 bytes');
  }
}

/** The ASCII key location the preimage must hold: `/<circuit>?vk=<sha256 of the bundled .verifier>`. */
export function keyLocationNeedle(circuit: Circuit, verifierSha256: string): Uint8Array {
  return encoder.encode(`/${circuit}?vk=${verifierSha256}`);
}

/** 422 `wrong-key` unless the preimage (R[0..o]) names this circuit with the bundled verifier key. */
export function checkKeyLocation(req: ProveRequest, verifierSha256: string): void {
  const needle = keyLocationNeedle(req.circuit, verifierSha256);
  if (indexOf(req.request.subarray(0, req.offset), needle) < 0) {
    throw new ApiError(
      422,
      'wrong-key',
      `the request is not for ${req.circuit} with this package's verifier key (vk ${verifierSha256}); ` +
        'it was built for another key set or another circuit',
    );
  }
}

/** SCALE compact encoding of a length, as midnight-serialize writes a `Vec<u8>`'s length. */
export function compactLength(n: number): Uint8Array {
  if (!Number.isInteger(n) || n < 0 || n > 0xffff_ffff) throw new RangeError(`length out of range: ${n}`);
  if (n < 1 << 6) return Uint8Array.of(n << 2);
  if (n < 1 << 14) {
    const v = (n << 2) | 0b01;
    return Uint8Array.of(v & 0xff, v >>> 8);
  }
  if (n < 1 << 30) {
    const v = ((n << 2) | 0b10) >>> 0;
    return Uint8Array.of(v & 0xff, (v >>> 8) & 0xff, (v >>> 16) & 0xff, v >>> 24);
  }
  return Uint8Array.of(0b11, n & 0xff, (n >>> 8) & 0xff, (n >>> 16) & 0xff, n >>> 24);
}

/** The bytes before and after the prover key: body = prefix | pk | suffix. */
export function spliceParts(
  req: ProveRequest,
  proverKeyLength: number,
  verifierKey: Uint8Array,
  ir: Uint8Array,
): { prefix: Uint8Array; suffix: Uint8Array; total: number } {
  const prefix = concat([req.request.subarray(0, req.offset), Uint8Array.of(0x01), compactLength(proverKeyLength)]);
  const suffix = concat([
    compactLength(verifierKey.length),
    verifierKey,
    compactLength(ir.length),
    ir,
    req.request.subarray(req.offset + 1),
  ]);
  return { prefix, suffix, total: prefix.length + proverKeyLength + suffix.length };
}

export function concat(parts: readonly Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

export function startsWith(bytes: Uint8Array, prefix: Uint8Array): boolean {
  if (bytes.length < prefix.length) return false;
  for (let i = 0; i < prefix.length; i++) if (bytes[i] !== prefix[i]) return false;
  return true;
}

export function indexOf(haystack: Uint8Array, needle: Uint8Array): number {
  return Buffer.from(haystack.buffer, haystack.byteOffset, haystack.byteLength).indexOf(
    Buffer.from(needle.buffer, needle.byteOffset, needle.byteLength),
  );
}
