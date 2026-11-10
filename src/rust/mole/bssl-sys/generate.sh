#!/usr/bin/env bash
# Regenerates lib.rs: bindgen over workerd's BoringSSL headers, allowlisted to the symbols the
# act-rs and ihat-rs BoringSSL backends name. Needs bindgen (`cargo install bindgen-cli`) and a
# fetched BoringSSL (`bazel fetch @ssl//:crypto`).
# Usage: generate.sh <act-rs checkout> <ihat-rs checkout>
set -euo pipefail
cd "$(dirname "$0")"
ssl="$(bazel info output_base)/external/boringssl+"
functions=$(cat "$1/src/backend/boringssl.rs" "$2/src/backend/boringssl.rs" |
  grep -o 'bssl_sys::[A-Za-z0-9_]*' | sed 's/bssl_sys:://' | sort -u | grep -E '^[A-Z0-9]+_' |
  grep -vE '^(BIGNUM|BN_CTX|BN_MONT_CTX|EC_GROUP|EC_POINT|SHA256_CTX)$' | paste -sd'|')
out=$(mktemp)
bindgen "$ssl/include/openssl/bn.h" --use-core --rustified-enum=point_conversion_form_t \
  --allowlist-function "($functions)" --allowlist-type '(SHA256_CTX|point_conversion_form_t)' \
  --no-doc-comments --merge-extern-blocks --blocklist-type '(bignum_st|BIGNUM|BN_ULONG)' \
  --raw-line '#[repr(C)] pub struct bignum_st { _unused: [u8; 0] } pub type BIGNUM = bignum_st;' \
  -o "$out" -- -I"$ssl/include" \
  -include openssl/ec.h -include openssl/sha2.h -include openssl/rand.h -include openssl/err.h \
  -include openssl/mem.h
{ sed -n '1,/^#!\[allow(unsafe_code/p' lib.rs; echo; sed 1d "$out"; } > lib.rs.new
mv lib.rs.new lib.rs
rm "$out"
