// Unit tests of I-62b's request rules and splice (bun test). Synthetic data only; the optional golden
// test at the end runs when GOLDEN_VECTORS and GOLDEN_KEYS point at the AA 00062 P1 vectors and a key set.

import { describe, expect, test } from 'bun:test';
import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { PROVE_TAG } from '../src/config.ts';
import { parseSha256Sums } from '../src/keys.ts';
import {
  ApiError,
  checkKeyLocation,
  compactLength,
  concat,
  decodeBase64,
  encodeBase64,
  parseProveRequest,
  spliceParts,
} from '../src/splice.ts';

const enc = new TextEncoder();
const VK = 'ab'.repeat(32);

/** TAG | preimage holding the key location | 0x00 | tail. */
function synthetic(circuit: string, vk = VK, tail: number[] = [1, ...new Array(32).fill(7)]) {
  const preimage = enc.encode(`\x02\x05contract:${'cd'.repeat(32)}/${circuit}?vk=${vk}\x09rest-of-preimage`);
  const head = concat([enc.encode(PROVE_TAG), preimage]);
  const request = concat([head, Uint8Array.of(0), Uint8Array.from(tail)]);
  return { request, offset: head.length };
}

function body(circuit: string, request: Uint8Array, offset: number) {
  return { circuit, proofRequest: encodeBase64(request), keyMaterialOffset: offset };
}

function apiError(f: () => unknown): ApiError {
  try {
    f();
  } catch (e) {
    if (e instanceof ApiError) return e;
    throw e;
  }
  throw new Error('expected an ApiError');
}

describe('parseProveRequest', () => {
  const c = 'open_swap_shielded_with_ed25519';

  test('accepts a well-formed request', () => {
    const { request, offset } = synthetic(c);
    const r = parseProveRequest(body(c, request, offset));
    expect(r.circuit).toBe(c);
    expect(r.offset).toBe(offset);
    expect(r.request).toEqual(request);
  });

  test('accepts a tail without a binding input (00)', () => {
    const { request, offset } = synthetic(c, VK, [0]);
    expect(parseProveRequest(body(c, request, offset)).offset).toBe(offset);
  });

  test('unknown circuit → 404 unknown-circuit (checked first)', () => {
    const e = apiError(() => parseProveRequest({ circuit: 'register_device', proofRequest: '!!', keyMaterialOffset: 'x' }));
    expect([e.status, e.code]).toEqual([404, 'unknown-circuit']);
  });

  test.each([
    ['not an object', 'x'],
    ['an array', []],
    ['null', null],
    ['circuit not a string', { circuit: 5, proofRequest: '', keyMaterialOffset: 1 }],
    ['proofRequest missing', { circuit: c, keyMaterialOffset: 1 }],
    ['proofRequest unpadded', { circuit: c, proofRequest: 'YWI', keyMaterialOffset: 1 }],
    ['proofRequest not base64', { circuit: c, proofRequest: 'a$b=', keyMaterialOffset: 1 }],
  ])('%s → 400 bad-request', (_name, value) => {
    const e = apiError(() => parseProveRequest(value));
    expect([e.status, e.code]).toEqual([400, 'bad-request']);
  });

  test('keyMaterialOffset not an integer → 400', () => {
    const { request, offset } = synthetic(c);
    for (const o of [String(offset), offset + 0.5, null, Number.NaN]) {
      const e = apiError(() => parseProveRequest({ circuit: c, proofRequest: encodeBase64(request), keyMaterialOffset: o }));
      expect([e.status, e.code]).toEqual([400, 'bad-request']);
    }
  });

  test('a proofRequest over 64 KiB → 413 too-large', () => {
    const big = new Uint8Array(64 * 1024 + 1);
    const e = apiError(() => parseProveRequest(body(c, big, 100)));
    expect([e.status, e.code]).toEqual([413, 'too-large']);
  });

  test('splice rules: tag, R[o] = 0x00, tail, offset range → 400', () => {
    const { request, offset } = synthetic(c);
    const badTag = request.slice();
    badTag[0] = 0x4e; // 'N'
    const badZero = request.slice();
    badZero[offset] = 1;
    const shortTail = synthetic(c, VK, [1, 1, 2]);
    const badTailTag = synthetic(c, VK, [2, ...new Array(32).fill(0)]);
    const longNone = synthetic(c, VK, [0, 0]);
    for (const [r, o] of [
      [badTag, offset],
      [badZero, offset],
      [shortTail.request, shortTail.offset],
      [badTailTag.request, badTailTag.offset],
      [longNone.request, longNone.offset],
      [request, 3],
      [request, request.length - 1],
      [request, -1],
      [request, offset - 1],
    ] as const) {
      const e = apiError(() => parseProveRequest(body(c, r, o)));
      expect([e.status, e.code]).toEqual([400, 'bad-request']);
    }
  });
});

describe('checkKeyLocation', () => {
  test('passes when the preimage names the circuit and the bundled vk', () => {
    const { request, offset } = synthetic('withdraw_shielded_with_ed25519');
    expect(() => checkKeyLocation(parseProveRequest(body('withdraw_shielded_with_ed25519', request, offset)), VK)).not.toThrow();
  });

  test('another verifier key → 422 wrong-key', () => {
    const { request, offset } = synthetic('withdraw_shielded_with_ed25519', 'ef'.repeat(32));
    const e = apiError(() => checkKeyLocation(parseProveRequest(body('withdraw_shielded_with_ed25519', request, offset)), VK));
    expect([e.status, e.code]).toEqual([422, 'wrong-key']);
  });

  test('a request for another circuit → 422 wrong-key (withdraw_unshielded asked as withdraw_shielded)', () => {
    const { request, offset } = synthetic('withdraw_unshielded_with_ed25519');
    const e = apiError(() => checkKeyLocation(parseProveRequest(body('withdraw_shielded_with_ed25519', request, offset)), VK));
    expect([e.status, e.code]).toEqual([422, 'wrong-key']);
  });

  test('the key location must be in the preimage, not in the tail', () => {
    // A tail of 01 + 32 bytes cannot hold it, but check the search window anyway: only R[0..o].
    const { request, offset } = synthetic('append_inbox_with_ed25519', 'ef'.repeat(32));
    const e = apiError(() => checkKeyLocation(parseProveRequest(body('append_inbox_with_ed25519', request, offset)), VK));
    expect(e.code).toBe('wrong-key');
  });
});

describe('compactLength (SCALE)', () => {
  test.each([
    [0, [0x00]],
    [1, [0x04]],
    [63, [0xfc]],
    [64, [0x01, 0x01]],
    [16383, [0xfd, 0xff]],
    [16384, [0x02, 0x00, 0x01, 0x00]],
    [579137691, [0x6e, 0xc2, 0x13, 0x8a]], // (n << 2) | 2 = 0x8a13c26e, a prover key's length
    [2 ** 30, [0x03, 0x00, 0x00, 0x00, 0x40]],
  ])('%d', (n, bytes) => {
    expect([...compactLength(n)]).toEqual(bytes);
  });
});

describe('spliceParts', () => {
  test('prefix = R[0..o] | 01 | len pk, suffix = len vk | vk | len ir | ir | R[o+1..]', () => {
    const { request, offset } = synthetic('append_inbox_with_ed25519');
    const req = parseProveRequest(body('append_inbox_with_ed25519', request, offset));
    const vk = Uint8Array.of(9, 9, 9);
    const ir = new Uint8Array(70).fill(5);
    const { prefix, suffix, total } = spliceParts(req, 100, vk, ir);
    // 100 → (100 << 2) | 1 = 0x0191; 3 → 0x0c; 70 → (70 << 2) | 1 = 0x0119 (little-endian).
    expect(prefix).toEqual(concat([request.subarray(0, offset), Uint8Array.of(1), Uint8Array.of(0x91, 0x01)]));
    expect(suffix).toEqual(concat([Uint8Array.of(0x0c), vk, Uint8Array.of(0x19, 0x01), ir, request.subarray(offset + 1)]));
    expect(total).toBe(prefix.length + 100 + suffix.length);
  });
});

describe('base64', () => {
  test('round trip and strictness', () => {
    const b = Uint8Array.of(0, 255, 1, 2, 3);
    expect(decodeBase64(encodeBase64(b))).toEqual(b);
    expect(decodeBase64('AP8BAgM')).toBeUndefined(); // no padding
    expect(decodeBase64('AP8B-gM=')).toBeUndefined(); // base64url
    expect(decodeBase64('')).toEqual(new Uint8Array());
  });
});

describe('SHA256SUMS', () => {
  test('parses the committed list', () => {
    const sums = parseSha256Sums(readFileSync(join(import.meta.dir, '../keys/SHA256SUMS'), 'utf8'));
    expect(sums.size).toBe(17);
    expect(sums.get('keyset-21493588.txt')).toBe('21493588f30536e0f409dcf79deea54878f0c2cf6fee601a2359e54a776d5c5e');
  });
});

// The P1 golden check: the package's splice of each captured key-less request with the key set's
// files equals, byte for byte (by SHA-256), the body the Night Market relay sent rc.8.
const GOLDEN_VECTORS = process.env.GOLDEN_VECTORS;
const GOLDEN_KEYS = process.env.GOLDEN_KEYS;
describe.skipIf(!GOLDEN_VECTORS || !GOLDEN_KEYS || !existsSync(`${GOLDEN_VECTORS}/vectors.json`))('golden splice', () => {
  const vectors = GOLDEN_VECTORS ? JSON.parse(readFileSync(`${GOLDEN_VECTORS}/vectors.json`, 'utf8')).vectors : [];
  for (const v of vectors as Array<{
    vector: string;
    circuit: string;
    keyMaterialOffset: number;
    request: { file: string };
    relayBody: { bytes: number; sha256: string };
  }>) {
    test(v.vector, () => {
      const request = new Uint8Array(readFileSync(`${GOLDEN_VECTORS}/${v.request.file}`));
      const req = parseProveRequest(body(v.circuit, request, v.keyMaterialOffset));
      // The package's flat layout, or a compiler key set's (keys/<c>.prover, zkir/<c>.bzkir).
      const file = (name: string, sub: string) =>
        existsSync(`${GOLDEN_KEYS}/${name}`) ? `${GOLDEN_KEYS}/${name}` : `${GOLDEN_KEYS}/${sub}/${name}`;
      const pk = readFileSync(file(`${v.circuit}.prover`, 'keys'));
      const vk = new Uint8Array(readFileSync(file(`${v.circuit}.verifier`, 'keys')));
      const ir = new Uint8Array(readFileSync(file(`${v.circuit}.bzkir`, 'zkir')));
      checkKeyLocation(req, createHash('sha256').update(vk).digest('hex'));
      const { prefix, suffix, total } = spliceParts(req, pk.length, vk, ir);
      const h = createHash('sha256').update(prefix).update(pk).update(suffix).digest('hex');
      expect(total).toBe(v.relayBody.bytes);
      expect(h).toBe(v.relayBody.sha256);
    }, 60_000);
  }
});
