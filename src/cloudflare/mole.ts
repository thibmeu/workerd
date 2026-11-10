// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

// `cloudflare:mole`, under the experimental `mole_crypto` flag: a WebCrypto-shaped `subtle` for
// the MOLE schemes, on the native implementation in src/rust/mole (see its README.md).
//
// Algorithms are `{ name: 'EC-IHATv1-P256-SHA256' }` and
// `{ name: 'ACTv1-P256-SHA256', balanceBits }`. The name is the pinned construction and encoding;
// every call names it and, for EC-ACT, the balance width, and both must match the key.
//
// This module runs in the Worker's realm, on builtins the Worker's code can replace, so its own
// checks and copies hold only while those builtins do. The native side checks, whatever this
// module passes, byte lengths and shared backing, amounts, extractability, EC-ACT usages and the
// one-use EC-IHAT state, and runs every operation under the key's own suite and balance width.
// (An EC-IHAT private key only ever has `sign`; verifying with a public key needs no permission.)
// Contexts and messages are bytes, challenge digests 32 bytes, amounts bigints.

import { default as native } from 'cloudflare-internal:mole';
import type * as types from 'cloudflare-internal:mole';

type Usage = 'sign' | 'verify';
// The supported suites. An incompatible change to either needs a new name, so a library upgrade
// that changes its protocol context fails here instead of silently renaming the suite.
const IHAT = 'EC-IHATv1-P256-SHA256';
const ACT = 'ACTv1-P256-SHA256';
if (native.ihatProfile() !== IHAT || native.actProfile() !== ACT) {
  throw new Error('cloudflare:mole: the linked libraries do not run the pinned suites.');
}
type Name = typeof IHAT | typeof ACT;
type Native =
  | types.IhatPrivateKey
  | types.IhatPublicKey
  | types.ActPrivateKey
  | types.ActPublicKey;

interface KeyAlgorithm {
  name: Name;
  balanceBits?: number;
}

// Contexts carry a 16-bit length prefix in both schemes; no message of the supported shapes
// (Anchor Sets of up to 1024 keys, balances of up to 64 bits) comes near the message bound.
const MAX_CONTEXT = 0xffff;
const MAX_MESSAGE = 0x10000;
const DIGEST_LENGTH = 32;

const token = Symbol();
const handles = new WeakMap<object, Native>();
const states = new WeakMap<object, types.IhatContinuation>();

class MoleKey {
  readonly type: 'private' | 'public';
  readonly extractable: boolean;
  readonly algorithm: Readonly<KeyAlgorithm>;
  readonly usages: readonly Usage[];

  constructor(
    key: symbol,
    type: 'private' | 'public',
    extractable: boolean,
    algorithm: KeyAlgorithm,
    usages: Usage[],
    handle: Native
  ) {
    if (key !== token) throw new TypeError('Illegal constructor.');
    this.type = type;
    this.extractable = extractable;
    this.algorithm = Object.freeze({ ...algorithm });
    this.usages = Object.freeze(usages);
    handles.set(this, handle);
    Object.freeze(this);
  }
}

// An EC-IHAT Anchor's state between `commit` and `sign`. The state itself stays native, in this
// isolate: it answers one `sign` call, through the key and issuance context that created it, and
// cannot be exported, cloned or imported.
class MoleState {
  constructor(key: symbol, handle: types.IhatContinuation) {
    if (key !== token) throw new TypeError('Illegal constructor.');
    states.set(this, handle);
    Object.freeze(this);
  }
}

function fail(name: string, message: string): never {
  throw new DOMException(message, name);
}

// A copy, so that nothing the caller runs later changes the bytes in use.
function bytes(value: unknown, what: string, max: number): Uint8Array {
  let view: Uint8Array;
  if (value instanceof ArrayBuffer) {
    view = new Uint8Array(value);
  } else if (ArrayBuffer.isView(value) && value.buffer instanceof ArrayBuffer) {
    view = new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  } else {
    throw new TypeError(`${what} must be an ArrayBuffer or a view of one.`);
  }
  if (view.byteLength > max) fail('DataError', `${what} is too long.`);
  return view.slice();
}

function digest(value: unknown, what: string): Uint8Array {
  const result = bytes(value, what, DIGEST_LENGTH);
  if (result.byteLength !== DIGEST_LENGTH) fail('DataError', `${what} must be 32 bytes.`);
  return result;
}

function amount(value: unknown, what: string, key: KeyAlgorithm): bigint {
  if (typeof value !== 'bigint') throw new TypeError(`${what} must be a bigint.`);
  if (value < 0n || value >= 1n << BigInt(key.balanceBits as number)) {
    throw new RangeError(`${what} is outside the balance width.`);
  }
  return value;
}

function object(value: unknown, what: string): Record<string, unknown> {
  if (typeof value !== 'object' || value === null) throw new TypeError(`${what} must be an object.`);
  return value as Record<string, unknown>;
}

// The name and balance width of an algorithm, read once.
function algorithm(value: unknown): KeyAlgorithm {
  const { name, balanceBits } = object(value, 'algorithm');
  if (name !== IHAT && name !== ACT) {
    fail('NotSupportedError', 'Unrecognized algorithm name.');
  }
  if (name === IHAT) return { name };
  if (
    typeof balanceBits !== 'number' ||
    !Number.isInteger(balanceBits) ||
    balanceBits < 1 ||
    balanceBits > 64
  ) {
    throw new TypeError('EC-ACT balanceBits must be an integer from 1 to 64.');
  }
  return { name, balanceBits };
}

// Splits the requested usages as WebCrypto does, rejecting any the key cannot have.
function usagesFor(usages: unknown, allowed: readonly Usage[]): Usage[] {
  if (!Array.isArray(usages)) throw new TypeError('usages must be an array.');
  const requested: unknown[] = [...usages];
  for (const usage of requested) {
    if (!allowed.includes(usage as Usage)) {
      fail('SyntaxError', `Usage ${String(usage)} is not valid for this key.`);
    }
  }
  return allowed.filter((usage) => requested.includes(usage));
}

function privateUsages(usages: unknown, allowed: readonly Usage[]): Usage[] {
  const result = usagesFor(usages, allowed);
  if (result.length === 0) fail('SyntaxError', 'A private key needs a usage.');
  return result;
}

// The native key of `key`, which must have the algorithm `alg` names and every usage in `usages`.
function handle<T extends Native>(
  key: unknown,
  alg: KeyAlgorithm,
  type: 'private' | 'public',
  usages: Usage[]
): T {
  const found = handles.get(key as object);
  if (found === undefined) throw new TypeError('key must be a cloudflare:mole key.');
  const k = key as MoleKey;
  if (
    k.type !== type ||
    k.algorithm.name !== alg.name ||
    k.algorithm.balanceBits !== alg.balanceBits
  ) {
    fail('InvalidAccessError', `The key is not a ${type} key of this algorithm.`);
  }
  for (const usage of usages) {
    if (!k.usages.includes(usage)) {
      fail('InvalidAccessError', `The key does not have the ${usage} usage.`);
    }
  }
  return found as T;
}

function makeKey(
  type: 'private' | 'public',
  extractable: boolean,
  alg: KeyAlgorithm,
  usages: Usage[],
  handle: Native
): MoleKey {
  return new MoleKey(token, type, extractable, alg, usages, handle);
}

class MoleSubtle {
  async generateKey(
    alg: unknown,
    extractable: boolean,
    usages: unknown
  ): Promise<{ privateKey: MoleKey; publicKey: MoleKey }> {
    const a = algorithm(alg);
    const exportable = !!extractable;
    if (a.name === IHAT) {
      const all = usagesFor(usages, ['sign', 'verify']);
      const sign = privateUsages(all.filter((usage) => usage === 'sign'), ['sign']);
      const secret = native.ihatGenerate(exportable);
      return {
        privateKey: makeKey('private', exportable, a, sign, secret),
        publicKey: makeKey('public', true, a, all.filter((usage) => usage === 'verify'), secret.publicKey()),
      };
    }
    const keyUsages = privateUsages(usages, ['sign', 'verify']);
    const secret = native.actGenerate(
      a.balanceBits as number,
      exportable,
      keyUsages.includes('sign'),
      keyUsages.includes('verify')
    );
    return {
      privateKey: makeKey('private', exportable, a, keyUsages, secret),
      publicKey: makeKey('public', true, a, [], secret.publicKey()),
    };
  }

  // Formats: 'raw' (a 33-byte compressed public key), 'ec-ihat-seed' (the 48-byte seed of an
  // EC-IHAT private key) and 'ec-act-scalar' (the 32-byte big-endian scalar of an EC-ACT private
  // key).
  async importKey(
    format: string,
    keyData: unknown,
    alg: unknown,
    extractable: boolean,
    usages: unknown
  ): Promise<MoleKey> {
    const a = algorithm(alg);
    const data = bytes(keyData, 'keyData', 48);
    const exportable = !!extractable;
    if (format === 'raw' && a.name === IHAT) {
      const handle = native.ihatImportPublic(data);
      return makeKey('public', exportable, a, usagesFor(usages, ['verify']), handle);
    }
    if (format === 'raw' && a.name === ACT) {
      const handle = native.actImportPublic(a.balanceBits as number, data);
      return makeKey('public', exportable, a, usagesFor(usages, []), handle);
    }
    if (format === 'ec-ihat-seed' && a.name === IHAT) {
      const keyUsages = privateUsages(usages, ['sign']);
      return makeKey('private', exportable, a, keyUsages, native.ihatImportSeed(data, exportable));
    }
    if (format === 'ec-act-scalar' && a.name === ACT) {
      const keyUsages = privateUsages(usages, ['sign', 'verify']);
      const handle = native.actImportScalar(
        a.balanceBits as number,
        data,
        exportable,
        keyUsages.includes('sign'),
        keyUsages.includes('verify')
      );
      return makeKey('private', exportable, a, keyUsages, handle);
    }
    fail('NotSupportedError', `Format ${format} is not supported for this algorithm.`);
  }

  async exportKey(format: string, key: unknown): Promise<ArrayBuffer> {
    const found = handles.get(key as object);
    if (found === undefined) throw new TypeError('key must be a cloudflare:mole key.');
    const k = key as MoleKey;
    if (!k.extractable) fail('InvalidAccessError', 'The key is not extractable.');
    if (format === 'raw' && k.type === 'public') {
      return (found as types.IhatPublicKey | types.ActPublicKey).export();
    }
    if (format === 'ec-ihat-seed' && k.algorithm.name === IHAT && k.type === 'private') {
      return (found as types.IhatPrivateKey).exportSeed();
    }
    if (format === 'ec-act-scalar' && k.algorithm.name === ACT && k.type === 'private') {
      return (found as types.ActPrivateKey).exportScalar();
    }
    fail('NotSupportedError', `Format ${format} is not supported for this key.`);
  }

  // EC-IHAT `Commit`, run by the Anchor: { name: IHAT, issuanceContext }.
  async commit(
    alg: unknown,
    privateKey: unknown
  ): Promise<{ commitment: ArrayBuffer; state: MoleState }> {
    const a = algorithm(alg);
    if (a.name !== IHAT) fail('NotSupportedError', 'commit is EC-IHAT only.');
    const ctx = bytes(object(alg, 'algorithm').issuanceContext, 'issuanceContext', MAX_CONTEXT);
    const continuation = handle<types.IhatPrivateKey>(privateKey, a, 'private', ['sign']).commit(ctx);
    return {
      commitment: continuation.commitment().slice().buffer,
      state: new MoleState(token, continuation),
    };
  }

  // EC-IHAT `Respond`: { name: IHAT, issuanceContext, state }, data = challenge.
  // EC-ACT `IssueResponse`: { name: ACT, balanceBits, credentialContext,
  //   operation: 'issue', initialCredits }, data = issuance request, verified first.
  // EC-ACT `VerifySpend` and `IssueRefund`: { ..., operation: 'refund', challengeDigest,
  //   expectedCost, expectedAllowance, returnCredits }, data = presentation (the spend message).
  //   Needs both usages; the spend must have the expected amounts and verify, once, before the
  //   refund is signed. Record the spend's nullifier before releasing the refund.
  async sign(alg: unknown, privateKey: unknown, data: unknown): Promise<ArrayBuffer> {
    const a = algorithm(alg);
    const o = object(alg, 'algorithm');
    if (a.name === IHAT) {
      const ctx = bytes(o.issuanceContext, 'issuanceContext', MAX_CONTEXT);
      const state = states.get(o.state as object);
      if (state === undefined) throw new TypeError('state must be a cloudflare:mole state.');
      const challenge = bytes(data, 'data', MAX_MESSAGE);
      return handle<types.IhatPrivateKey>(privateKey, a, 'private', ['sign']).respond(state, ctx, challenge);
    }
    const ctx = bytes(o.credentialContext, 'credentialContext', MAX_CONTEXT);
    if (o.operation === 'issue') {
      const credits = amount(o.initialCredits, 'initialCredits', a);
      const request = bytes(data, 'data', MAX_MESSAGE);
      return handle<types.ActPrivateKey>(privateKey, a, 'private', ['sign']).issue(request, ctx, credits);
    }
    if (o.operation === 'refund') {
      const challengeDigest = digest(o.challengeDigest, 'challengeDigest');
      const cost = amount(o.expectedCost, 'expectedCost', a);
      const allowance = amount(o.expectedAllowance, 'expectedAllowance', a);
      const credits = amount(o.returnCredits, 'returnCredits', a);
      const spend = bytes(data, 'data', MAX_MESSAGE);
      const moderator = handle<types.ActPrivateKey>(privateKey, a, 'private', ['sign', 'verify']);
      return moderator.refund(spend, ctx, challengeDigest, cost, allowance, credits);
    }
    fail('NotSupportedError', 'Unrecognized EC-ACT sign operation.');
  }

  // EC-IHAT `VerifyRedemption`: { name: IHAT, operation: 'redeem', issuanceContext,
  //   redemptionContext }, key = the Anchor Set (public keys, in the Moderator's order, none
  //   repeated), signature = redemption, data = challenge digest.
  // EC-ACT `VerifySpend`: { name: ACT, balanceBits, operation: 'spend',
  //   credentialContext, expectedCost, expectedAllowance }, key = the private key, signature =
  //   presentation (the spend message), data = challenge digest.
  // Neither enforces single use: reject a recorded nullifier, and record it before granting.
  async verify(alg: unknown, key: unknown, signature: unknown, data: unknown): Promise<boolean> {
    const a = algorithm(alg);
    const o = object(alg, 'algorithm');
    if (a.name === IHAT && o.operation === 'redeem') {
      const ctxIss = bytes(o.issuanceContext, 'issuanceContext', MAX_CONTEXT);
      const ctxRed = bytes(o.redemptionContext, 'redemptionContext', MAX_CONTEXT);
      if (!Array.isArray(key)) throw new TypeError('key must be an array of keys.');
      const anchors = [...(key as unknown[])].map((anchor) =>
        handle<types.IhatPublicKey>(anchor, a, 'public', ['verify'])
      );
      const redemption = bytes(signature, 'signature', MAX_MESSAGE);
      return native.ihatVerify(anchors, redemption, ctxIss, ctxRed, digest(data, 'data'));
    }
    if (a.name === ACT && o.operation === 'spend') {
      const ctx = bytes(o.credentialContext, 'credentialContext', MAX_CONTEXT);
      const cost = amount(o.expectedCost, 'expectedCost', a);
      const allowance = amount(o.expectedAllowance, 'expectedAllowance', a);
      const spend = bytes(signature, 'signature', MAX_MESSAGE);
      const moderator = handle<types.ActPrivateKey>(key, a, 'private', ['verify']);
      return moderator.verifySpend(spend, ctx, digest(data, 'data'), cost, allowance);
    }
    fail('NotSupportedError', 'Unrecognized verify operation.');
  }

  // EC-ACT `ProveSpend`, run by the Client: alg = { name: ACT, balanceBits,
  // credentialContext }, from the Credential's secret bytes. Resolves to the presentation (the
  // spend message) and the secret spend state that finalizes the refund.
  async present(
    alg: unknown,
    credential: unknown,
    params: unknown
  ): Promise<{ presentation: ArrayBuffer; state: ArrayBuffer }> {
    const a = algorithm(alg);
    if (a.name !== ACT) fail('NotSupportedError', 'present is EC-ACT only.');
    const ctx = bytes(object(alg, 'algorithm').credentialContext, 'credentialContext', MAX_CONTEXT);
    const p = object(params, 'params');
    const challengeDigest = digest(p.challengeDigest, 'challengeDigest');
    const cost = amount(p.cost, 'cost', a);
    const allowance = amount(p.allowance, 'allowance', a);
    const secret = bytes(credential, 'credential', MAX_MESSAGE);
    const [presentation, state] = native.actPresent(
      a.balanceBits as number,
      secret,
      ctx,
      challengeDigest,
      cost,
      allowance
    );
    secret.fill(0);
    return { presentation, state };
  }
}

export const crypto = Object.freeze({ subtle: Object.freeze(new MoleSubtle()) });
