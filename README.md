# solana-proof-server: the Night Market prover

Night Market's largest zero-knowledge proofs need about **12 GB of memory**. This image lets you
make them on your own machine, with one command, so that the market's server does not have to.

It is a tech demo for the Solana ↔ Midnight journey. On a real network, this will be provided.

## Run it

```sh
docker run --rm --name night-market-prover -p 127.0.0.1:6300:6300 --memory 12g \
  ghcr.io/midnight-experiments/solana-proof-server:0.1.0-21493588
```

Then, in Night Market's **Local Data** tab, enter `http://localhost:6300` and click **Test**.

- **Memory.** Give the container about 12 GB.
  - Measured on a 12-CPU arm64 machine: the proof server peaked at 7.7 GiB per proof, and the container at 7.8 GiB.
  - Each proof took 23–24 s.
  - The 12 GB leaves headroom: an earlier run of the plain proof server, without the package's restart after each proof, reached 11 GiB over three proofs.
  - On Docker Desktop (macOS, Windows), first raise the VM's memory: Settings → Resources → Memory, at least 12 GB.
  - Without enough memory the proof server is stopped by the system. The package then answers `503 out-of-memory` and restarts it.
- **This machine only.** `-p 127.0.0.1:6300:6300` publishes the port on localhost only. Inside the container the package listens on `0.0.0.0:6300`.
- **Check it:** `curl http://localhost:6300/version`.
- **Download size:** about 0.65 GB compressed, 2.7 GB on disk. The four prover keys are 552 MiB each.

The page shows the exact command, pinned by digest, once the image is published.

### Browsers

Your browser asks before an `https://` page may call `http://localhost`:
- **Chrome and Edge:** a "local network access" prompt;
- **Firefox:** the "device apps and services" prompt;
- **Brave:** a setting, `brave://settings/content/localhostAccess`;
- **Safari:** it blocks the call. Use an online prover URL instead.

### Privacy

The prover sees the private inputs of the transaction it proves: the coins, the amounts and the accounts. Run your own, or use only an online prover you trust. The package never logs request or response bodies. It needs no network access at run time.

## What it holds

| Part | What |
|---|---|
| Proof server | The official `midnightntwrk/proof-server:9.0.0-rc.8`, copied by digest (`sha256:2666c7bd7b4517f8ad135565387f98d14347a9ac715c6c466d4a8a852b545ecf`). It runs as a child process, with one worker. |
| Keys | Four circuits of the Passport account contract (Ed25519 arm), all k = 18. Each has its prover key (about 552 MiB), verifier key and binary ZKIR. |
| Key set | `21493588f30536e0f409dcf79deea54878f0c2cf6fee601a2359e54a776d5c5e`: the set Night Market's relay pins and the deployed account contracts use. See [`keys/`](keys/README.md). |
| Parameters | `bls_midnight_2p18`, the KZG parameters for k = 18, checked by SHA-256 at build time. |
| Front | [`src/`](src/): a small Bun server. It takes a proof request **without keys**, adds the bundled keys, and streams the result to the proof server. |
| Base | `oven/bun:1.3.11` (Debian), by digest. |

The four circuits:

| Circuit | Used for |
|---|---|
| `append_inbox_with_ed25519` | re-filing a change coin |
| `open_swap_shielded_with_ed25519` | making and taking offers |
| `withdraw_shielded_with_ed25519` | shielded withdrawals, and Bridge out's first transaction |
| `withdraw_unshielded_with_ed25519` | unshielded withdrawals |

The image tag is `<package version>-21493588`. A new key set means a new release of the keys and a new image tag.

## API

The page calls two routes. Every answer is JSON.

### `GET /version`

```json
{"api": 1, "package": "0.1.0", "proofServer": "9.0.0-rc.8",
 "keySet": "21493588f30536e0f409dcf79deea54878f0c2cf6fee601a2359e54a776d5c5e",
 "circuits": ["append_inbox_with_ed25519", "open_swap_shielded_with_ed25519",
              "withdraw_shielded_with_ed25519", "withdraw_unshielded_with_ed25519"],
 "busy": false, "machine": {"cpus": 12, "memoryBytes": 12884901888}}
```

- `busy` is true while a proof runs.
- `machine` describes the container: its limits when it has any, else the host's.

### `POST /prove-circuit`

The request has `content-type: application/json` and a body of at most 256 KiB:

```json
{"circuit": "open_swap_shielded_with_ed25519", "proofRequest": "<base64>", "keyMaterialOffset": 2585}
```

`proofRequest` is the ledger's key-less `/prove` body for one proof, `HEAD | 0x00 | TAIL`, at most 64 KiB. `keyMaterialOffset` is the index of that `0x00`.

The package then does four things, in this order:
1. It checks that the circuit is one of its four.
2. It checks the request's shape:
   - the request starts with `midnight:(proof-preimage-versioned,option(proving-data),option(fr-bls)):`;
   - the byte at the offset is `0x00`;
   - what follows the offset is `00`, or `01` and 32 bytes.
3. It checks that the request names the circuit with the bundled verifier key: `/<circuit>?vk=<sha256 of the .verifier>`.
4. It sends the proof server this body:

   ```
   R[0..o] | 0x01 | len pk | pk | len vk | vk | len ir | ir | R[o+1..]
   ```

   Each `len` is SCALE's compact length. The prover key's SHA-256 is checked as the key is streamed.

A proof is answered `200 {"proof": "<base64>", "proveMs": 20123}`. The proof is rc.8's tagged `ProofVersioned`: 8,028 bytes for these circuits.

Errors are answered `{"error": {"code", "message"}}`:

| Status | `code` | When |
|---|---|---|
| 400 | `bad-request` | not JSON, a wrong field, or a request that is not a key-less `/prove` body |
| 404 | `unknown-circuit` | a circuit this package does not hold |
| 413 | `too-large` | a body over 256 KiB, or a `proofRequest` over 64 KiB |
| 422 | `wrong-key` | a request for another key set, or for another circuit |
| 429 | `busy` | a proof is already running (`Retry-After: 30`); the package proves one at a time |
| 502 | `prover-error` | the proof server refused the request (its text, at most 500 characters) |
| 503 | `starting` | the proof server is not ready yet |
| 503 | `out-of-memory` | the proof server stopped during the proof; the package restarts it |
| 504 | `timeout` | no proof after 900 s |

### CORS

- Every answer echoes the request's `Origin` in `Access-Control-Allow-Origin`, with `Vary: Origin` and no credentials.
- `OPTIONS` on any path answers 204 with:
  - `Access-Control-Allow-Methods: GET, POST, OPTIONS`;
  - `Access-Control-Allow-Headers: content-type`;
  - `Access-Control-Max-Age: 600`;
  - `Access-Control-Allow-Private-Network: true`.

## How it behaves

- **One proof at a time.** A second request while one runs gets `429 busy`.
- **A fresh proof server for every proof.** The proof server keeps memory between proofs: in one test, 3.9 → 7.1 GiB resident after three proofs. The package therefore restarts it after each proof, which takes about a second.
- **Out of memory.** The proof server raises its own OOM score, so the system stops it rather than the front. The front answers the request `503 out-of-memory` and restarts it.
- **A client that goes away.** If the page closes the request, the proof is abandoned and the proof server is restarted.
- **Logs.** Only methods, paths, statuses, sizes, times and the proof server's lifecycle are logged, never a body. The proof server runs at its INFO level, which logs no bodies either.
- **Settings** (environment variables, rarely needed):
  - `PROOF_TIMEOUT_SECONDS`: default 900;
  - `START_WAIT_SECONDS`: how long a request waits for the proof server to start, default 30.

## Build it

```sh
./build.sh          # → solana-proof-server:<VERSION>-21493588, for this machine's platform
```

The build downloads the release [`keys-21493588`](https://github.com/midnight-experiments/solana-proof-server/releases/tag/keys-21493588) and checks the keys three ways:
- BuildKit checks each file against its pinned SHA-256;
- [`scripts/check-keys.sh`](scripts/check-keys.sh) checks all of them against [`keys/SHA256SUMS`](keys/SHA256SUMS), the key-set fingerprint, and that each verifier key belongs to the key set;
- the front re-checks the small files at every start, and each prover key as it streams it.

The keys are never compiled here.

### CI

[`.github/workflows/image.yml`](.github/workflows/image.yml):
- **Pull requests:** the unit tests, then a `linux/amd64` build and a smoke test. Nothing is pushed.
- **A tag `v<VERSION>`** (or a manual run on `main`): a build for `linux/amd64` and `linux/arm64`, pushed as `ghcr.io/midnight-experiments/solana-proof-server:<VERSION>-21493588` with the workflow's own token (`packages: write`).

### Tests

```sh
docker run --rm -v "$PWD":/repo:ro -w /repo oven/bun:1.3.11 bun test        # the request rules and the splice
bun test/e2e.ts --base http://127.0.0.1:6300                                  # a running package: version, CORS, refusals
bun test/e2e.ts --base http://127.0.0.1:6300 --vectors DIR --heavy            # + the golden proofs (about 12 GB)
```

`DIR` holds golden vectors: real proof requests captured from Night Market's relay (AA 00062 P1).
