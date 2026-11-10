// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

import assert from 'node:assert';

export const unavailable = {
  async test() {
    await assert.rejects(import('cloudflare:mole'));
    await assert.rejects(import('cloudflare-internal:mole'));
  },
};
