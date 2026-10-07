// The pins and settings of the Night Market prover package (AA 00062, interface I-62b).

/** The four k = 18 circuits of the Passport account contract (Ed25519 arm) this package proves, sorted. */
export const CIRCUITS = [
  'append_inbox_with_ed25519',
  'open_swap_shielded_with_ed25519',
  'withdraw_shielded_with_ed25519',
  'withdraw_unshielded_with_ed25519',
] as const;
export type Circuit = (typeof CIRCUITS)[number];

/** The key set's fingerprint: the SHA-256 of keys/keyset-21493588.txt (the relay's RELAY_KEYS_FINGERPRINT). */
export const KEY_SET = '21493588f30536e0f409dcf79deea54878f0c2cf6fee601a2359e54a776d5c5e';

/** The official proof server inside the image (checked against its own GET /version at every start). */
export const PROOF_SERVER_VERSION = '9.0.0-rc.8';

/** I-62b's API version. */
export const API_VERSION = 1;

/** The tag every key-less /prove body starts with (the ledger's tagged (preimage, Option<keys>, Option<Fr>)). */
export const PROVE_TAG = 'midnight:(proof-preimage-versioned,option(proving-data),option(fr-bls)):';

/** The tag every proof starts with (the ledger's tagged ProofVersioned). */
export const PROOF_TAG = 'midnight:proof-versioned:';

export const LIMITS = {
  /** POST /prove-circuit body (JSON). */
  bodyBytes: 256 * 1024,
  /** The decoded proofRequest (I-62a). */
  proofRequestBytes: 64 * 1024,
  /** rc.8's answer (I-62a: a proof is at most 64 KiB; 8,028 B measured). */
  proofBytes: 64 * 1024,
  /** rc.8's error text passed on as `message`. */
  errorTextChars: 500,
} as const;

function intFromEnv(name: string, fallback: number, min: number, max: number): number {
  const raw = process.env[name];
  if (raw === undefined || raw === '') return fallback;
  const n = Number(raw);
  if (!Number.isInteger(n) || n < min || n > max) {
    throw new Error(`${name} must be an integer in [${min}, ${max}], got ${JSON.stringify(raw)}`);
  }
  return n;
}

export interface Settings {
  /** The package's own version (the image tag is `<version>-21493588`). */
  packageVersion: string;
  /** Where the front listens inside the container (published with -p 127.0.0.1:6300:6300). */
  port: number;
  /** rc.8's internal port (never published). */
  proofServerPort: number;
  /** The rc.8 binary. */
  proofServerBin: string;
  /** Where the circuits' files and keys/SHA256SUMS + keys/keyset-21493588.txt are. */
  keysDir: string;
  /** rc.8's KZG params directory (MIDNIGHT_PP), baked into the image. */
  paramsDir: string;
  /** The front's own deadline for one proof (504 `timeout`). */
  proofTimeoutMs: number;
  /** rc.8's --job-timeout, above the front's deadline (R2). */
  proofServerJobTimeoutSeconds: number;
  /** How long a request waits for rc.8 to (re)start before 503 `starting`. */
  startWaitMs: number;
  /** Chunk size used to stream the prover key to rc.8. */
  keyChunkBytes: number;
}

export function loadSettings(): Settings {
  const proofTimeoutSeconds = intFromEnv('PROOF_TIMEOUT_SECONDS', 900, 30, 3600);
  return {
    packageVersion: process.env.PACKAGE_VERSION || '0.0.0-dev',
    port: intFromEnv('PORT', 6300, 1, 65535),
    proofServerPort: intFromEnv('PROOF_SERVER_PORT', 6301, 1, 65535),
    proofServerBin: process.env.PROOF_SERVER_BIN || '/usr/local/bin/midnight-proof-server',
    keysDir: process.env.KEYS_DIR || '/opt/solana-proof-server/keys',
    paramsDir: process.env.MIDNIGHT_PP || '/opt/solana-proof-server/params',
    proofTimeoutMs: proofTimeoutSeconds * 1000,
    // rc.8 must never drop a job the front still waits for: 60 s above the front's deadline.
    proofServerJobTimeoutSeconds: proofTimeoutSeconds + 60,
    startWaitMs: intFromEnv('START_WAIT_SECONDS', 30, 1, 600) * 1000,
    keyChunkBytes: 16 * 1024 * 1024,
  };
}
