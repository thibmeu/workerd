# `cloudflare:mole` (experimental)

Native EC-IHAT and EC-ACT for MOLE, behind the experimental `mole_crypto` compatibility flag
(no enable date). Restricting it to accounts is platform configuration; workerd does not.

- `src/cloudflare/mole.ts`: `import { crypto } from 'cloudflare:mole'`, a WebCrypto-shaped
  `crypto.subtle`. It is never added to the global `crypto.subtle`, which rejects its keys.
- `src/rust/mole/`: `cloudflare-internal:mole`, Rust JSG resources over the BoringSSL backends of
  act-rs and ihat-rs.
- `src/rust/mole/bssl-sys/`: the `bssl-sys` those backends name, generated bindings to the
  BoringSSL workerd already links (`@ssl//:crypto`); there is no second BoringSSL.
  `build/deps/rust.MODULE.bazel` redirects the crates.io placeholder to it.
- `src/cloudflare/internal/test/mole/`: test, benchmark and fixtures.

## Suites

| `name`                  | Library, revision                                                                                   |
| ----------------------- | --------------------------------------------------------------------------------------------------- |
| `EC-IHATv1-P256-SHA256` | ihat-rs `ed756147ac9a1cc530d718e749c0fae8090fda7c`, feature `boringssl`                             |
| `ACTv1-P256-SHA256`     | act-rs `f1bd64b90408677662bb9f96915d8dc0e58e1ad6`, feature `boringssl` (SHAKE128 from `shake` 0.1) |

The algorithm `name` identifies one pinned construction and its encodings; an incompatible change
to either needs a new name, not a new meaning for this one. `mole.ts` holds the names as
constants and refuses to load if the linked libraries' `PROTOCOL_CONTEXT` differs, so a library
upgrade cannot silently change what a name runs. These are the revisions guac pins, so the wire
formats are guac's. Every call names the suite (and `balanceBits` for EC-ACT, 1 to 64), which must
equal the key's; any other name is `NotSupportedError`.

## Formats

All encodings are the libraries' canonical ones; decoders reject noncanonical points and scalars,
the identity, wrong lengths and trailing bytes.

| Value | Bytes |
| --- | --- |
| public key (`'raw'`, both) | 33, compressed SEC1 |
| `'ec-ihat-seed'` (private) | 48, the seed of `G.DeriveKeyPair`; kept only if extractable |
| `'ec-act-scalar'` (private) | 32, big-endian scalar |
| EC-IHAT commitment / challenge / response | 66 / 32 / 96 |
| EC-IHAT redemption | `Redemption::encoded_len(n)` for an Anchor Set of `n` |
| EC-ACT issuance request / response / refund | 129 / 137 / 137 |
| EC-ACT presentation | the `SpendMessage` |
| EC-ACT presentation `state` | `ClientSpendState::to_bytes()`, secret, for guac's `finalize_refund` |
| challenge digest | exactly 32 |

Contexts are at most 65535 bytes, other messages at most 65536 bytes; both `mole.ts` and the
native side check this before any copy. Inputs are copied once, at the call, from an `ArrayBuffer` or a view of one
(`SharedArrayBuffer` is rejected). Amounts are bigints below `2^balanceBits`, never coerced.

### GUAC encodings

The adapter takes contexts and digests as bytes and uses them as given: it neither appends the
balance width nor hashes anything.

- `credentialContext` is a public domain binding, not a secret and not per request: the same
  bytes go to issuance, presentation, spend verification and refund for every credential of a
  deployment. It is GUAC's `config.credential_context_bytes()`: the configured credential context
  bytes followed by `balanceBits` as one byte, appended exactly once, by GUAC; the adapter passes
  them through. The per-presentation binding is `challengeDigest`, below.
- `challengeDigest` is GUAC's challenge digest: the SHA-256 of the canonical challenge encoding,
  `type || vector(challenge payload)`. It is not a hash of JSON or of raw HTTP bytes.
- `issuanceContext` and `redemptionContext` are GUAC's EC-IHAT context bytes, unchanged.

The fixtures and the benchmark use act-rs `benches/webcrypto`'s raw ASCII contexts
(`benchmark-context`, `benchmark-issuance-context`, `benchmark-redemption-context`), not
GUAC-derived ones; the cryptographic cost is the same.

## Operations

```js
const IHAT = { name: 'EC-IHATv1-P256-SHA256' };
const ACT = { name: 'ACTv1-P256-SHA256', balanceBits: 16 };

// Anchor
const { commitment, state } = await subtle.commit({ ...IHAT, issuanceContext }, anchorKey);
const response = await subtle.sign({ ...IHAT, issuanceContext, state }, anchorKey, challenge);
// Moderator
const ok = await subtle.verify({ ...IHAT, operation: 'redeem', issuanceContext, redemptionContext },
    anchorSet, redemption, digest32);
const issued = await subtle.sign({ ...ACT, credentialContext, operation: 'issue', initialCredits },
    moderatorKey, issuanceRequest);
const valid = await subtle.verify({ ...ACT, operation: 'spend', credentialContext, expectedCost,
    expectedAllowance }, moderatorKey, presentation, digest32);
const refund = await subtle.sign({ ...ACT, credentialContext, operation: 'refund', challengeDigest,
    expectedCost, expectedAllowance, returnCredits }, moderatorKey, presentation);
// Client
const { presentation, state } = await subtle.present({ ...ACT, credentialContext }, credential,
    { challengeDigest, cost, allowance });
```

- Issuance verifies the request before signing. Refund checks the spend's cost and allowance
  against `expectedCost` and `expectedAllowance` before verifying, verifies it once, and signs
  from act-rs's `VerifiedSpend`; it needs both `sign` and `verify`. Spend verification takes the
  Moderator's private key with `verify`.
- Neither verification enforces single use. Reject a recorded nullifier, and record it before
  granting anything; guac reads the nullifier from the redemption or presentation bytes.
- The Anchor Set is ordered and may not repeat a key (compared by encoding; ihat-rs itself does
  not check). It holds 1 to 1024 keys; only 16 have been benchmarked.
- `mole.ts` runs in the Worker's realm, on builtins the Worker can replace, so it is not the
  boundary, and its copies and checks hold only while those builtins do. The native side checks,
  for whatever it is passed, byte lengths and `SharedArrayBuffer` backing (before reading any
  bytes), extractability, EC-ACT usages, amount bounds, expected amounts, Anchor Set duplicates
  and the one-use EC-IHAT state, and runs every operation under the key's suite and balance
  width. An EC-IHAT private key only ever has `sign`.

## The EC-IHAT state

Two responses from one Anchor state, or a response to a state whose nonces the caller knows,
disclose the Anchor's private key. So the state never leaves native memory: `commit` returns an
opaque `state` object, bound to the key and issuance context, which answers one `sign` call and
is consumed by any attempt, including a failed one. It cannot be exported, imported, cloned or
constructed.

**Durable state is unimplemented.** A commit and its response must run in the same isolate, and
the state dies with it. A cross-request flow (commit in one request, respond in another, possibly
on another machine) cannot ship until state import/export is solved: the state must be
authenticated, bound to the key and context, and consumed at most once across every copy of the
storage it lives in, which no isolate-local check can guarantee.

## Limits of this experiment

- Native allocations (keys, `Params`, Anchor states, contexts kept with states) are not reported
  to V8's external memory accounting or to heap snapshots. Anchor states are bounded only by the
  isolate's JavaScript heap holding their wrappers.
- `Params` are built once per thread and balance width, and kept for the thread's lifetime.
- Errors carry only the libraries' fixed messages, never inputs or secrets. Secret copies made by
  the adapter are zeroized; copies in JavaScript buffers (exported keys, credentials, presentation
  states) are not.
- `bssl-sys/layout-check.c++` checks `SHA256_CTX`, the one struct the backends hold by value,
  against BoringSSL's header at build time; the other types are opaque.

## Tests and benchmark

```sh
bazel test //src/cloudflare/internal/test/mole:all
just wd-bench //src/cloudflare/internal/test/mole:mole-bench@
# pinned to one core, as the baseline was:
taskset -c 2 bazel run --config=benchmark //src/cloudflare/internal/test/mole:mole-bench@
```

`fixtures.json` was generated by `generator/` (standalone Cargo, the same revisions, RustCrypto
backend, so the native BoringSSL backend is checked against it):
`cargo run --release --manifest-path generator/Cargo.toml > fixtures.json`.

The benchmark times whole calls from JavaScript: argument checks and copies, the native call and
the promise, minus the runner's own per-call cost. `respond` consumes a state per call; each batch
gets fresh states from untimed setup. The workload is act-rs `benches/webcrypto`'s: L = 16, an
Anchor Set of 16, cost `(2^L - 2) / 2`, allowance 0, refund `cost / 2`, the same contexts. Its
digests are 32 bytes (SHA-256 of that benchmark's 26-byte digest string), since this API requires
32.

### Comparing with the Wasm baseline

The Wasm "host" baseline (`act-rs/benches/webcrypto`, `node run.mjs 16 16 host`, timed over HTTP
as `(t(n + 1) - t(1)) / n`) runs different revisions: act-rs `7dc2eb6` and ihat-rs `350ec81`,
the `host-scalar-mul` branches, built for Emscripten. Its `issue_response` row measures verify and
issue together, as `verify_and_issue_response` does here. The two differ in revisions, digest
length and harness, so their ratio is indicative, not a like-for-like measurement. A like-for-like
baseline needs the `host` feature ported to the revisions above, which has not been done.
