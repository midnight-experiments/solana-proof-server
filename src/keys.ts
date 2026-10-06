// The bundled key material, checked at every start against keys/SHA256SUMS and the key-set
// fingerprint. The prover keys (about 552 MiB each) stay on disk: their SHA-256 is checked as they
// are streamed to rc.8 on every proof (see prover.ts), so a damaged file never yields a proof.

import { createHash } from 'node:crypto';
import { readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { CIRCUITS, type Circuit, KEY_SET } from './config.ts';

export interface CircuitKeys {
  circuit: Circuit;
  proverPath: string;
  proverBytes: number;
  proverSha256: string;
  verifierKey: Uint8Array;
  verifierSha256: string;
  ir: Uint8Array;
}

export type KeyBundle = ReadonlyMap<Circuit, CircuitKeys>;

const sha256 = (bytes: Uint8Array) => createHash('sha256').update(bytes).digest('hex');

/** `<sha256>  <file>` lines → file → sha256. */
export function parseSha256Sums(text: string): Map<string, string> {
  const out = new Map<string, string>();
  for (const line of text.split('\n')) {
    if (line.trim() === '') continue;
    const m = /^([0-9a-f]{64}) [ *](\S+)$/.exec(line);
    if (!m) throw new Error(`SHA256SUMS: malformed line ${JSON.stringify(line)}`);
    out.set(m[2]!, m[1]!);
  }
  return out;
}

export function loadKeyBundle(keysDir: string): KeyBundle {
  const sums = parseSha256Sums(readFileSync(join(keysDir, 'SHA256SUMS'), 'utf8'));
  const keyset = readFileSync(join(keysDir, `keyset-${KEY_SET.slice(0, 8)}.txt`));
  if (sha256(keyset) !== KEY_SET) throw new Error(`the key-set preimage does not hash to the fingerprint ${KEY_SET}`);
  const keysetLines = new Set(keyset.toString('utf8').split('\n'));
  const want = (file: string): string => {
    const h = sums.get(file);
    if (!h) throw new Error(`SHA256SUMS has no entry for ${file}`);
    return h;
  };
  const bundle = new Map<Circuit, CircuitKeys>();
  for (const circuit of CIRCUITS) {
    const verifierKey = new Uint8Array(readFileSync(join(keysDir, `${circuit}.verifier`)));
    const ir = new Uint8Array(readFileSync(join(keysDir, `${circuit}.bzkir`)));
    const verifierSha256 = sha256(verifierKey);
    if (verifierSha256 !== want(`${circuit}.verifier`)) throw new Error(`${circuit}.verifier does not match SHA256SUMS`);
    if (sha256(ir) !== want(`${circuit}.bzkir`)) throw new Error(`${circuit}.bzkir does not match SHA256SUMS`);
    if (!keysetLines.has(`account/${circuit} ${verifierSha256}`)) {
      throw new Error(`${circuit}.verifier is not in key set ${KEY_SET}`);
    }
    const proverPath = join(keysDir, `${circuit}.prover`);
    bundle.set(circuit, {
      circuit,
      proverPath,
      proverBytes: statSync(proverPath).size,
      proverSha256: want(`${circuit}.prover`),
      verifierKey,
      verifierSha256,
      ir,
    });
  }
  return bundle;
}
