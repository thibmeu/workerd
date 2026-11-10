// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

// Whole-call times of cloudflare:mole: argument checks and copies, the native call, and the
// promise. Same workload as act-rs benches/webcrypto (L = 16, Anchor Set of 16, cost
// (2^L - 2) / 2, allowance 0, refund cost / 2), except that challenge digests are 32 bytes. See
// src/rust/mole/README.md.

import { crypto as mole } from 'cloudflare:mole';
import f from 'fixtures.json';

const { subtle } = mole;
const hex = (s) => Uint8Array.from(s.match(/../g), (b) => parseInt(b, 16));
const IHAT = { name: 'EC-IHATv1-P256-SHA256' };
const ACT = { name: 'ACTv1-P256-SHA256', balanceBits: f.balanceBits };
const digest = hex(f.challengeDigest);
const credentialContext = hex(f.credentialContext);
const commitAlg = { ...IHAT, issuanceContext: hex(f.issuanceContext) };
const redeem = {
  ...IHAT,
  operation: 'redeem',
  issuanceContext: hex(f.issuanceContext),
  redemptionContext: hex(f.redemptionContext),
};
const spend = {
  ...ACT,
  operation: 'spend',
  credentialContext,
  expectedCost: BigInt(f.cost),
  expectedAllowance: BigInt(f.allowance),
};
const refund = { ...spend, operation: 'refund', challengeDigest: digest, returnCredits: BigInt(f.refund) };
const issue = { ...ACT, operation: 'issue', credentialContext, initialCredits: BigInt(f.balance) };
const present = { ...ACT, credentialContext };
const presentParams = { challengeDigest: digest, cost: BigInt(f.cost), allowance: BigInt(f.allowance) };
const challenge = new Uint8Array(32).fill(7);
// `respond` consumes a state per call: each batch gets fresh ones, made untimed.
const RESPOND_BATCH = 64;
// A verification that fails would time the rejection path.
const valid = (ok) => {
  if (ok !== true) throw new Error('verification failed');
};

export default {
  async bench(b) {
    const anchor = await subtle.importKey('ec-ihat-seed', hex(f.anchorSeeds[8]), IHAT, false, ['sign']);
    const set = await Promise.all(
      f.anchorPublicKeys.map((k) => subtle.importKey('raw', hex(k), IHAT, false, ['verify']))
    );
    const moderator = await subtle.importKey('ec-act-scalar', hex(f.moderatorScalar), ACT, false, [
      'sign',
      'verify',
    ]);
    const redemption = hex(f.redemption);
    const request = hex(f.issueRequest);
    const spendMessage = hex(f.spend);
    const credential = hex(f.credential);
    // Untimed: the presentation this benchmark proves is one the Moderator accepts.
    const proved = await subtle.present(present, credential, presentParams);
    valid(await subtle.verify(spend, moderator, proved.presentation, digest));

    b.run('EC-IHAT keygen', async () =>
      b.blackBox(await subtle.generateKey(IHAT, false, ['sign', 'verify']))
    );
    b.run('EC-IHAT commit', async () => b.blackBox(await subtle.commit(commitAlg, anchor)));
    b.run(
      'EC-IHAT respond',
      async (states) => {
        const { state } = states.pop();
        b.blackBox(await subtle.sign({ ...commitAlg, state }, anchor, challenge));
      },
      {
        // Warmup batches grow past RESPOND_BATCH calls; `commit` above already warmed this path.
        warmup: 0,
        batch: RESPOND_BATCH,
        setup: () =>
          Promise.all(Array.from({ length: RESPOND_BATCH }, () => subtle.commit(commitAlg, anchor))),
      }
    );
    b.run('EC-IHAT verify_redemption', async () =>
      valid(await subtle.verify(redeem, set, redemption, digest))
    );
    b.run('EC-ACT verify_and_issue_response', async () =>
      b.blackBox(await subtle.sign(issue, moderator, request))
    );
    b.run('EC-ACT verify_spend', async () =>
      valid(await subtle.verify(spend, moderator, spendMessage, digest))
    );
    b.run('EC-ACT verify_and_refund', async () =>
      b.blackBox(await subtle.sign(refund, moderator, spendMessage))
    );
    b.run('EC-ACT prove_spend', async () =>
      b.blackBox(await subtle.present(present, credential, presentParams))
    );
  },
};
