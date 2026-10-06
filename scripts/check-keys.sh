#!/bin/sh
# Checks the key files of the image against the committed keys/SHA256SUMS and the key-set fingerprint.
# Run by the Dockerfile on the downloaded release assets, before they are copied into the image.
#
#   check-keys.sh DIR    DIR holds <circuit>.{prover,verifier,bzkir}, SHA256SUMS and keyset-21493588.txt
set -eu

FINGERPRINT=21493588f30536e0f409dcf79deea54878f0c2cf6fee601a2359e54a776d5c5e
CIRCUITS="append_inbox_with_ed25519 open_swap_shielded_with_ed25519 withdraw_shielded_with_ed25519 withdraw_unshielded_with_ed25519"

cd "$1"
list=$(mktemp)

# 1. Every bundled file, byte for byte, against the committed list. (The release's .zkir files, the
#    same circuits as JSON for reading, are not bundled.)
for c in $CIRCUITS; do
  for ext in prover verifier bzkir; do
    grep -E "^[0-9a-f]{64}  $c\.$ext\$" SHA256SUMS >>"$list" || { echo "SHA256SUMS has no entry for $c.$ext" >&2; exit 1; }
  done
done
grep -E "^[0-9a-f]{64}  keyset-21493588\.txt\$" SHA256SUMS >>"$list" || { echo "SHA256SUMS has no entry for the key-set preimage" >&2; exit 1; }
[ "$(wc -l <"$list")" -eq 13 ] || { echo "expected 13 entries" >&2; exit 1; }
sha256sum -c "$list"

# 2. The key-set preimage hashes to the fingerprint the relay pins.
actual=$(sha256sum keyset-21493588.txt | cut -d' ' -f1)
[ "$actual" = "$FINGERPRINT" ] || { echo "keyset-21493588.txt hashes to $actual, not $FINGERPRINT" >&2; exit 1; }

# 3. Each bundled verifier key belongs to that key set.
for c in $CIRCUITS; do
  vk=$(sha256sum "$c.verifier" | cut -d' ' -f1)
  grep -qx "account/$c $vk" keyset-21493588.txt || { echo "$c.verifier ($vk) is not in key set $FINGERPRINT" >&2; exit 1; }
done

rm -f "$list"
echo "keys OK: 12 files = SHA256SUMS, key set $FINGERPRINT, 4 verifier keys in it"
