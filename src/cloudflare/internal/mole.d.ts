// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

// Type definitions for the Rust implementation, src/rust/mole.

export interface IhatPrivateKey {
  publicKey(): IhatPublicKey;
  exportSeed(): ArrayBuffer;
  commit(ctxIss: Uint8Array): IhatContinuation;
  respond(
    continuation: IhatContinuation,
    ctxIss: Uint8Array,
    challenge: Uint8Array
  ): ArrayBuffer;
}
export interface IhatContinuation {
  commitment(): Uint8Array;
}
export interface IhatPublicKey {
  export(): ArrayBuffer;
}
export interface ActPrivateKey {
  publicKey(): ActPublicKey;
  exportScalar(): ArrayBuffer;
  issue(request: Uint8Array, ctxCred: Uint8Array, amount: bigint): ArrayBuffer;
  verifySpend(
    spend: Uint8Array,
    ctxCred: Uint8Array,
    digest: Uint8Array,
    cost: bigint,
    allowance: bigint
  ): boolean;
  refund(
    spend: Uint8Array,
    ctxCred: Uint8Array,
    digest: Uint8Array,
    cost: bigint,
    allowance: bigint,
    refund: bigint
  ): ArrayBuffer;
}
export interface ActPublicKey {
  export(): ArrayBuffer;
  balanceBits(): number;
}

export function ihatProfile(): string;
export function actProfile(): string;
export function ihatGenerate(extractable: boolean): IhatPrivateKey;
export function ihatImportSeed(
  seed: Uint8Array,
  extractable: boolean
): IhatPrivateKey;
export function ihatImportPublic(bytes: Uint8Array): IhatPublicKey;
export function ihatVerify(
  anchors: IhatPublicKey[],
  redemption: Uint8Array,
  ctxIss: Uint8Array,
  ctxRed: Uint8Array,
  digest: Uint8Array
): boolean;
export function actGenerate(
  balanceBits: number,
  extractable: boolean,
  sign: boolean,
  verify: boolean
): ActPrivateKey;
export function actImportScalar(
  balanceBits: number,
  bytes: Uint8Array,
  extractable: boolean,
  sign: boolean,
  verify: boolean
): ActPrivateKey;
export function actImportPublic(
  balanceBits: number,
  bytes: Uint8Array
): ActPublicKey;
export function actPresent(
  balanceBits: number,
  credential: Uint8Array,
  ctxCred: Uint8Array,
  digest: Uint8Array,
  amount: bigint,
  allowance: bigint
): [ArrayBuffer, ArrayBuffer];
