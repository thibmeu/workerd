// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

// lib.rs passes SHA256_CTX by value; these are the numbers its bindgen asserts check against.
// They fail to compile if the BoringSSL workerd builds lays SHA256_CTX out differently.

#include <openssl/sha2.h>

#include <cstddef>

static_assert(sizeof(SHA256_CTX) == 112);
static_assert(alignof(SHA256_CTX) == 4);
static_assert(offsetof(SHA256_CTX, h) == 0);
static_assert(offsetof(SHA256_CTX, Nl) == 32);
static_assert(offsetof(SHA256_CTX, Nh) == 36);
static_assert(offsetof(SHA256_CTX, data) == 40);
static_assert(offsetof(SHA256_CTX, num) == 104);
static_assert(offsetof(SHA256_CTX, md_len) == 108);
