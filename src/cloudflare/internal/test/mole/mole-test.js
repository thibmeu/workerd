// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

import assert from 'node:assert';
import { crypto as mole } from 'cloudflare:mole';
import f from 'fixtures.json';

const { subtle } = mole;
const hex = (s) => Uint8Array.from(s.match(/../g), (b) => parseInt(b, 16));
const toHex = (b) => Buffer.from(b).toString('hex');
const IHAT = { name: 'EC-IHATv1-P256-SHA256' };
const ACT = { name: 'ACTv1-P256-SHA256', balanceBits: f.balanceBits };
const digest = hex(f.challengeDigest);
const redeem = {
  ...IHAT,
  operation: 'redeem',
  issuanceContext: hex(f.issuanceContext),
  redemptionContext: hex(f.redemptionContext),
};
const spend = {
  ...ACT,
  operation: 'spend',
  credentialContext: hex(f.credentialContext),
  expectedCost: BigInt(f.cost),
  expectedAllowance: BigInt(f.allowance),
};
const refund = {
  ...spend,
  operation: 'refund',
  challengeDigest: digest,
  returnCredits: BigInt(f.refund),
};
// Respond accepts any nonzero scalar; the Client's challenge is GUAC's.
const challenge = new Uint8Array(32).fill(7);

const anchors = () =>
  Promise.all(
    f.anchorPublicKeys.map((k) => subtle.importKey('raw', hex(k), IHAT, false, ['verify']))
  );
const moderator = (usages = ['sign', 'verify'], extractable = false) =>
  subtle.importKey('ec-act-scalar', hex(f.moderatorScalar), ACT, extractable, usages);

export const notGlobal = {
  async test() {
    assert.strictEqual(globalThis.crypto.subtle.commit, undefined);
    const key = await moderator();
    await assert.rejects(globalThis.crypto.subtle.sign(spend, key, digest), TypeError);
    const [anchor] = await anchors();
    await assert.rejects(subtle.exportKey('raw', anchor), { name: 'InvalidAccessError' });
    assert.throws(() => new anchor.constructor(Symbol(), 'public'), TypeError);
  },
};

export const ihatVerify = {
  async test() {
    const set = await anchors();
    assert.strictEqual(await subtle.verify(redeem, set, hex(f.redemption), digest), true);
    const tampered = hex(f.redemption);
    tampered[40] ^= 1;
    assert.strictEqual(await subtle.verify(redeem, set, tampered, digest), false);
    assert.strictEqual(await subtle.verify(redeem, [...set].reverse(), hex(f.redemption), digest), false);
    assert.strictEqual(await subtle.verify(redeem, set, hex(f.redemption), new Uint8Array(32)), false);
    await assert.rejects(subtle.verify(redeem, set, hex(f.redemption), digest.subarray(1)), {
      name: 'DataError',
    });
    // Repeated keys, by bytes rather than by object.
    const again = await subtle.importKey('raw', hex(f.anchorPublicKeys[0]), IHAT, false, ['verify']);
    await assert.rejects(subtle.verify(redeem, [...set.slice(1), again], hex(f.redemption), digest), {
      name: 'DataError',
    });
    await assert.rejects(subtle.verify({ ...redeem, name: 'EC-IHATv2-P256-SHA256' }, set, hex(f.redemption), digest), {
      name: 'NotSupportedError',
    });
    await assert.rejects(
      subtle.verify(redeem, set, new SharedArrayBuffer(8), digest),
      TypeError
    );
  },
};

export const ihatState = {
  async test() {
    const { privateKey, publicKey } = await subtle.generateKey(IHAT, false, ['sign', 'verify']);
    assert.deepStrictEqual(privateKey.usages, ['sign']);
    assert.deepStrictEqual(publicKey.usages, ['verify']);
    await assert.rejects(subtle.exportKey('ec-ihat-seed', privateKey), { name: 'InvalidAccessError' });
    assert.strictEqual((await subtle.exportKey('raw', publicKey)).byteLength, 33);

    const alg = { ...IHAT, issuanceContext: hex(f.issuanceContext) };
    const { commitment, state } = await subtle.commit(alg, privateKey);
    assert.strictEqual(commitment.byteLength, 66);
    assert.strictEqual((await subtle.sign({ ...alg, state }, privateKey, challenge)).byteLength, 96);
    await assert.rejects(subtle.sign({ ...alg, state }, privateKey, challenge), { name: 'OperationError' });

    // A rejected attempt consumes the state too.
    const second = (await subtle.commit(alg, privateKey)).state;
    const other = { ...alg, issuanceContext: new Uint8Array([1]) };
    await assert.rejects(subtle.sign({ ...other, state: second }, privateKey, challenge), {
      name: 'OperationError',
    });
    await assert.rejects(subtle.sign({ ...alg, state: second }, privateKey, challenge), {
      name: 'OperationError',
    });

    // Bound to its key, and copies carry nothing.
    const otherKey = (await subtle.generateKey(IHAT, false, ['sign'])).privateKey;
    const third = (await subtle.commit(alg, privateKey)).state;
    await assert.rejects(subtle.sign({ ...alg, state: third }, otherKey, challenge), {
      name: 'OperationError',
    });
    const fourth = (await subtle.commit(alg, privateKey)).state;
    await assert.rejects(subtle.sign({ ...alg, state: structuredClone(fourth) }, privateKey, challenge), TypeError);

    const seeded = await subtle.importKey('ec-ihat-seed', hex(f.anchorSeeds[3]), IHAT, true, ['sign']);
    assert.strictEqual(toHex(await subtle.exportKey('ec-ihat-seed', seeded)), f.anchorSeeds[3]);
  },
};

export const actModerator = {
  async test() {
    const key = await moderator();
    await assert.rejects(subtle.exportKey('ec-act-scalar', key), { name: 'InvalidAccessError' });
    const signOnly = await moderator(['sign'], true);
    assert.strictEqual(toHex(await subtle.exportKey('ec-act-scalar', signOnly)), f.moderatorScalar);

    const issue = { ...ACT, operation: 'issue', credentialContext: hex(f.credentialContext) };
    const response = await subtle.sign({ ...issue, initialCredits: BigInt(f.balance) }, key, hex(f.issueRequest));
    assert.strictEqual(response.byteLength, 33 + 3 * 32 + 8);
    await assert.rejects(subtle.sign({ ...issue, initialCredits: 1 }, key, hex(f.issueRequest)), TypeError);
    await assert.rejects(subtle.sign({ ...issue, initialCredits: 1n << 16n }, key, hex(f.issueRequest)), RangeError);
    await assert.rejects(subtle.sign({ ...issue, initialCredits: 1n, balanceBits: 17 }, key, hex(f.issueRequest)), {
      name: 'InvalidAccessError',
    });

    assert.strictEqual(await subtle.verify(spend, key, hex(f.spend), digest), true);
    assert.strictEqual(await subtle.verify({ ...spend, expectedCost: 1n }, key, hex(f.spend), digest), false);
    const tampered = hex(f.spend);
    tampered[60] ^= 1;
    assert.strictEqual(await subtle.verify(spend, key, tampered, digest), false);
    await assert.rejects(subtle.verify(spend, signOnly, hex(f.spend), digest), { name: 'InvalidAccessError' });

    assert.strictEqual((await subtle.sign(refund, key, hex(f.spend))).byteLength, 33 + 3 * 32 + 8);
    await assert.rejects(subtle.sign(refund, signOnly, hex(f.spend)), { name: 'InvalidAccessError' });
    await assert.rejects(subtle.sign(refund, key, tampered), { name: 'OperationError' });
    // Policy inputs are checked before anything is signed.
    await assert.rejects(subtle.sign({ ...refund, expectedAllowance: 1n }, key, hex(f.spend)), {
      name: 'OperationError',
    });
    await assert.rejects(subtle.sign({ ...refund, challengeDigest: new Uint8Array(32) }, key, hex(f.spend)), {
      name: 'OperationError',
    });
    await assert.rejects(subtle.sign({ ...refund, returnCredits: BigInt(f.cost) + 1n }, key, hex(f.spend)), {
      name: 'DataError',
    });
  },
};

export const actPresent = {
  async test() {
    const params = { challengeDigest: digest, cost: BigInt(f.cost), allowance: 0n };
    const alg = { ...ACT, credentialContext: hex(f.credentialContext) };
    const { presentation, state } = await subtle.present(alg, hex(f.credential), params);
    assert.ok(state.byteLength > 0);
    assert.strictEqual(await subtle.verify(spend, await moderator(), presentation, digest), true);
    await assert.rejects(subtle.present(alg, hex(f.credential), { ...params, cost: BigInt(f.balance) + 1n }), {
      name: 'DataError',
    });
  },
};

// The Worker can replace the builtins mole.ts uses and reach the native keys; they still hold.
export const tamperedBuiltins = {
  async test() {
    const verifyOnly = await moderator(['verify']);
    const anchor = await subtle.importKey('ec-ihat-seed', hex(f.anchorSeeds[0]), IHAT, false, ['sign']);
    const get = WeakMap.prototype.get;
    const includes = Array.prototype.includes;
    const captured = [];
    WeakMap.prototype.get = function (key) {
      const value = get.call(this, key);
      if (value !== undefined) captured.push(value);
      return value;
    };
    Array.prototype.includes = () => true;
    try {
      await subtle.verify(spend, verifyOnly, hex(f.spend), digest);
      await subtle.sign(
        { ...ACT, operation: 'issue', credentialContext: hex(f.credentialContext), initialCredits: 1n },
        verifyOnly,
        hex(f.issueRequest)
      ).catch(() => {});
      await subtle.exportKey('ec-ihat-seed', anchor).catch(() => {});
    } finally {
      WeakMap.prototype.get = get;
      Array.prototype.includes = includes;
    }
    const [nativeModerator] = captured;
    assert.throws(() => nativeModerator.issue(hex(f.issueRequest), hex(f.credentialContext), 1n), {
      name: 'InvalidAccessError',
    });
    assert.throws(() => nativeModerator.exportScalar(), { name: 'InvalidAccessError' });
    const nativeAnchor = captured.find((value) => typeof value.exportSeed === 'function');
    assert.throws(() => nativeAnchor.exportSeed(), { name: 'InvalidAccessError' });
  },
};
