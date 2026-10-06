# solana-proof-server: the Night Market prover package (AA 00062).
#
# One image, run with one `docker run`:
#   - the official Midnight proof server 9.0.0-rc.8, copied by digest;
#   - the prover keys, verifier keys and binary ZKIR of the four k = 18 circuits of the Passport account
#     contract (Ed25519 arm), from the release `keys-21493588` (key set 21493588f305…5c5e);
#   - the KZG parameters those circuits need (k = 18), so a proof needs no download;
#   - a small Bun front (I-62b) that takes a proof request WITHOUT keys, adds the bundled keys, and
#     streams it to rc.8.
#
# Build: ./build.sh (or the CI workflow). The base images are pinned by digest (multi-arch indexes).

ARG BUN_IMAGE=oven/bun:1.3.11@sha256:0733e50325078969732ebe3b15ce4c4be5082f18c4ac1a0f0ca4839c2e4e42a7
ARG PROOF_SERVER_IMAGE=midnightntwrk/proof-server:9.0.0-rc.8@sha256:2666c7bd7b4517f8ad135565387f98d14347a9ac715c6c466d4a8a852b545ecf

FROM ${PROOF_SERVER_IMAGE} AS rc8

# ---------------------------------------------------------------------------------------------------
# The key files and params: downloaded once (on the build machine's own platform), each checked by
# BuildKit against its pinned SHA-256, then again against the committed keys/SHA256SUMS and the key
# set's fingerprint (scripts/check-keys.sh). The hashes below are keys/SHA256SUMS's.
FROM --platform=$BUILDPLATFORM ${BUN_IMAGE} AS keys
ARG KEYS_URL=https://github.com/midnight-experiments/solana-proof-server/releases/download/keys-21493588
ARG PARAMS_URL=https://srs.midnight.network
ADD --chmod=0444 --checksum=sha256:53f938d7d0f786b7a1d5cca4ba9c01c5859bbd40f21b4673fc83e7d185780563 ${KEYS_URL}/append_inbox_with_ed25519.prover /keys/append_inbox_with_ed25519.prover
ADD --chmod=0444 --checksum=sha256:989df8d807750995e709039af6155f69832b65d53c20c5355ebac51395999ed9 ${KEYS_URL}/open_swap_shielded_with_ed25519.prover /keys/open_swap_shielded_with_ed25519.prover
ADD --chmod=0444 --checksum=sha256:c12150086faceed0a8f70c18ecf765af882db8b0df34ea066fb4c19f5524cea9 ${KEYS_URL}/withdraw_shielded_with_ed25519.prover /keys/withdraw_shielded_with_ed25519.prover
ADD --chmod=0444 --checksum=sha256:d2fc058007943cffb7092c0de6b3a7a4d4c2f679e46178ba20f8eb046af7ad92 ${KEYS_URL}/withdraw_unshielded_with_ed25519.prover /keys/withdraw_unshielded_with_ed25519.prover
ADD --chmod=0444 --checksum=sha256:cf025f6a1f8e597b7b40d93ea6f3b7a9c8c55141d7e42e8e1854ab166d73376f ${KEYS_URL}/append_inbox_with_ed25519.verifier /keys/append_inbox_with_ed25519.verifier
ADD --chmod=0444 --checksum=sha256:8ba4a638edd1e8b8bfb9c53b98740c61e8a3cf7c6eca461b22490f8a7b695b7e ${KEYS_URL}/open_swap_shielded_with_ed25519.verifier /keys/open_swap_shielded_with_ed25519.verifier
ADD --chmod=0444 --checksum=sha256:0af6b9754da02f4b9dd919e5127de96b7d8a44ff318f23b3f4ed6429ad21ed91 ${KEYS_URL}/withdraw_shielded_with_ed25519.verifier /keys/withdraw_shielded_with_ed25519.verifier
ADD --chmod=0444 --checksum=sha256:2ee9cef2664825260653525f689ed4b79ffa3b5b4a2b1443338a41e65785503b ${KEYS_URL}/withdraw_unshielded_with_ed25519.verifier /keys/withdraw_unshielded_with_ed25519.verifier
ADD --chmod=0444 --checksum=sha256:4efbd16a849a1b40df80af728956241f61925400ecd36f11b1026ab39dce3b25 ${KEYS_URL}/append_inbox_with_ed25519.bzkir /keys/append_inbox_with_ed25519.bzkir
ADD --chmod=0444 --checksum=sha256:97574dce813d642673a393eea3774832a985577e9b7e67bcc08117af3f1d0997 ${KEYS_URL}/open_swap_shielded_with_ed25519.bzkir /keys/open_swap_shielded_with_ed25519.bzkir
ADD --chmod=0444 --checksum=sha256:456924009fd98c0e200cd87e1035dea6375fefb3ea38d045efbaec86731533d5 ${KEYS_URL}/withdraw_shielded_with_ed25519.bzkir /keys/withdraw_shielded_with_ed25519.bzkir
ADD --chmod=0444 --checksum=sha256:502821518612a9281a1b3d6a37735bc772f38a881fe36025769d56242cdad300 ${KEYS_URL}/withdraw_unshielded_with_ed25519.bzkir /keys/withdraw_unshielded_with_ed25519.bzkir
# All four circuits are k = 18 (rc.8's own POST /k). The hash is the one rc.8 itself checks
# (midnight-ledger base-crypto EXPECTED_DATA, bls_midnight_2p18).
ADD --chmod=0444 --checksum=sha256:e8436dc5d8b598f169c127c745135d889744007e6d384ff126df8d1332522f86 ${PARAMS_URL}/bls_midnight_2p18 /params/bls_midnight_2p18
COPY --chmod=0444 keys/SHA256SUMS keys/keyset-21493588.txt /keys/
COPY --chmod=0555 scripts/check-keys.sh /usr/local/bin/check-keys
RUN check-keys /keys

# ---------------------------------------------------------------------------------------------------
FROM ${BUN_IMAGE}

# rc.8 is a nix closure linked against the store's own glibc, so it runs on this Debian base as is.
# Its store path differs per architecture: found by glob, never hard-coded.
COPY --from=rc8 /nix /nix
RUN set -eu; \
    set -- /nix/store/*-ledger-*/bin/midnight-proof-server; \
    [ "$#" -eq 1 ] && [ -x "$1" ] || { echo "expected one midnight-proof-server, found: $*" >&2; exit 1; }; \
    ln -s "$1" /usr/local/bin/midnight-proof-server; \
    midnight-proof-server --help >/dev/null

# The keys: each prover key (about 552 MiB) in its own layer, then the small files.
ENV KEYS_DIR=/opt/solana-proof-server/keys \
    MIDNIGHT_PP=/opt/solana-proof-server/params
COPY --from=keys /params/bls_midnight_2p18 /opt/solana-proof-server/params/bls_midnight_2p18
COPY --from=keys /keys/append_inbox_with_ed25519.prover /opt/solana-proof-server/keys/
COPY --from=keys /keys/open_swap_shielded_with_ed25519.prover /opt/solana-proof-server/keys/
COPY --from=keys /keys/withdraw_shielded_with_ed25519.prover /opt/solana-proof-server/keys/
COPY --from=keys /keys/withdraw_unshielded_with_ed25519.prover /opt/solana-proof-server/keys/
COPY --from=keys /keys/*.verifier /keys/*.bzkir /keys/SHA256SUMS /keys/keyset-21493588.txt /opt/solana-proof-server/keys/

COPY src/ /opt/solana-proof-server/app/src/

ARG PACKAGE_VERSION=0.0.0-dev
ENV PACKAGE_VERSION=${PACKAGE_VERSION} \
    PORT=6300 \
    PROOF_SERVER_PORT=6301
LABEL org.opencontainers.image.title="solana-proof-server" \
      org.opencontainers.image.description="Night Market prover: Midnight proof server 9.0.0-rc.8 with the Passport account's four k=18 Ed25519 circuits (key set 21493588), behind a CORS front. Run: docker run --rm -p 127.0.0.1:6300:6300 --memory 12g <image>" \
      org.opencontainers.image.source="https://github.com/midnight-experiments/solana-proof-server" \
      org.opencontainers.image.version="${PACKAGE_VERSION}-21493588" \
      io.midnight-experiments.proof-server="9.0.0-rc.8" \
      io.midnight-experiments.key-set="21493588f30536e0f409dcf79deea54878f0c2cf6fee601a2359e54a776d5c5e"

USER bun
WORKDIR /opt/solana-proof-server/app
EXPOSE 6300
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD ["bun", "-e", "fetch('http://127.0.0.1:6300/version',{headers:{'user-agent':'solana-proof-server-healthcheck'}}).then(r=>process.exit(r.ok?0:1),()=>process.exit(1))"]
ENTRYPOINT ["bun", "src/main.ts"]
