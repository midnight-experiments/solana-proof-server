# The keys (release `keys-21493588`)

The image proves four circuits of the Passport account contract (Ed25519 arm), the ones too large for
an 8 GB server (k = 18):

- `open_swap_shielded_with_ed25519`: making and taking offers;
- `withdraw_shielded_with_ed25519`: shielded withdrawals and Bridge out's first transaction;
- `withdraw_unshielded_with_ed25519`: unshielded withdrawals;
- `append_inbox_with_ed25519`: re-filing a change coin.

Their files come from the key set whose fingerprint is
`21493588f30536e0f409dcf79deea54878f0c2cf6fee601a2359e54a776d5c5e`: the set Night Market's relay pins
(`RELAY_KEYS_FINGERPRINT`) and the deployed account contracts use. compactc 0.35.0
(`debb05f9414b9d1e176741c2be289bb32233f0fc`) compiled them. They are uploaded **once**, as assets of
the GitHub release [`keys-21493588`](https://github.com/midnight-experiments/solana-proof-server/releases/tag/keys-21493588),
and are never recompiled: a new key set means a new release and a new image tag.

| File | What it is |
|---|---|
| `SHA256SUMS` | The SHA-256 of every release asset (`sha256sum -c SHA256SUMS` in the download directory). |
| `keyset-21493588.txt` | The fingerprint's preimage: one line `<contract>/<circuit> <sha256 of its .verifier>` per verifier key of the whole set, sorted, newline-terminated. Its SHA-256 **is** the fingerprint. |

Per circuit the release holds `<circuit>.prover` (about 552 MiB), `<circuit>.verifier`, `<circuit>.bzkir`
(the binary ZKIR the proof server reads) and `<circuit>.zkir` (the same circuit as JSON, for reading).

## Checking a download

```sh
gh release download keys-21493588 --repo midnight-experiments/solana-proof-server --dir keys-21493588
cd keys-21493588
sha256sum -c ../keys/SHA256SUMS                       # every asset, byte for byte
sha256sum keyset-21493588.txt                         # = 21493588f305…5c5e, the fingerprint
for c in append_inbox_with_ed25519 open_swap_shielded_with_ed25519 \
         withdraw_shielded_with_ed25519 withdraw_unshielded_with_ed25519; do
  grep -qx "account/$c $(sha256sum "$c.verifier" | cut -d' ' -f1)" keyset-21493588.txt || echo "NOT IN THE KEY SET: $c"
done
```
