// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

//! `cloudflare-internal:mole`, the native half of `cloudflare:mole` (src/cloudflare/mole.ts):
//! EC-IHAT and EC-ACT on the BoringSSL backends of ihat-rs and act-rs. mole.ts runs on builtins
//! the Worker can replace, so this side checks what guards keys and messages itself: byte lengths
//! and backing (`checked`), amounts, extractability, EC-ACT usages and the one-use EC-IHAT state.
//! Byte arguments are `Uint8Array`s, amounts `BigInt`s. See README.md.

use std::pin::Pin;

use jsg_macros::jsg_method;
use jsg_macros::jsg_resource;

mod act;
mod ihat;

#[cxx::bridge(namespace = "workerd::rust::mole")]
#[expect(unsafe_code, reason = "the cxx bridge expands to unsafe FFI glue")]
mod ffi {
    #[namespace = "workerd::rust::jsg"]
    unsafe extern "C++" {
        include!("workerd/rust/jsg/ffi.h");

        type ModuleRegistry = jsg::v8::ffi::ModuleRegistry;
    }
    extern "Rust" {
        pub fn register_mole_module(registry: Pin<&mut ModuleRegistry>);
    }
}

/// Registers `cloudflare-internal:mole`. C++ calls this only with the `mole_crypto` flag.
pub fn register_mole_module(registry: Pin<&mut ffi::ModuleRegistry>) {
    jsg::modules::add_builtin(
        registry,
        "cloudflare-internal:mole",
        |lock| Ok(jsg::Rc::new(lock, MoleModule {})),
        jsg::modules::ModuleType::Internal,
    );
}

/// The module object: key generation and import, and the operations that take no private key.
#[jsg_resource]
pub struct MoleModule;

#[jsg_resource]
impl MoleModule {
    /// ihat-rs's `ctx_proto`, which mole.ts requires to equal its pinned suite name.
    #[jsg_method]
    fn ihat_profile(&self) -> String {
        String::from_utf8_lossy(ec_ihat::PROTOCOL_CONTEXT).into_owned()
    }

    /// act-rs's `ctx_proto`, which mole.ts requires to equal its pinned suite name.
    #[jsg_method]
    fn act_profile(&self) -> String {
        String::from_utf8_lossy(::act::PROTOCOL_CONTEXT).into_owned()
    }

    #[jsg_method]
    fn ihat_generate(&self, lock: &mut jsg::Lock, extractable: bool) -> jsg::Result<jsg::Rc<ihat::IhatPrivateKey>> {
        ihat::generate(lock, extractable)
    }

    #[jsg_method]
    fn ihat_import_seed<'s>(
        &self,
        lock: &mut jsg::Lock<'s>,
        seed: jsg::v8::Local<'s, jsg::v8::Uint8Array>,
        extractable: bool,
    ) -> jsg::Result<jsg::Rc<ihat::IhatPrivateKey>> {
        ihat::import_seed(lock, seed, extractable)
    }

    #[jsg_method]
    fn ihat_import_public<'s>(
        &self,
        lock: &mut jsg::Lock<'s>,
        bytes: jsg::v8::Local<'s, jsg::v8::Uint8Array>,
    ) -> jsg::Result<jsg::Rc<ihat::IhatPublicKey>> {
        ihat::import_public(lock, bytes)
    }

    #[jsg_method]
    fn ihat_verify<'s>(
        &self,
        lock: &mut jsg::Lock<'s>,
        anchors: Vec<jsg::Rc<ihat::IhatPublicKey>>,
        redemption: jsg::v8::Local<'s, jsg::v8::Uint8Array>,
        ctx_iss: jsg::v8::Local<'s, jsg::v8::Uint8Array>,
        ctx_red: jsg::v8::Local<'s, jsg::v8::Uint8Array>,
        digest: jsg::v8::Local<'s, jsg::v8::Uint8Array>,
    ) -> jsg::Result<bool> {
        ihat::verify(lock, &anchors, redemption, ctx_iss, ctx_red, digest)
    }

    #[jsg_method]
    fn act_generate(
        &self,
        lock: &mut jsg::Lock,
        balance_bits: u8,
        extractable: bool,
        sign: bool,
        verify: bool,
    ) -> jsg::Result<jsg::Rc<act::ActPrivateKey>> {
        act::generate(lock, balance_bits, extractable, act::Usages { sign, verify })
    }

    #[jsg_method]
    fn act_import_scalar<'s>(
        &self,
        lock: &mut jsg::Lock<'s>,
        balance_bits: u8,
        bytes: jsg::v8::Local<'s, jsg::v8::Uint8Array>,
        extractable: bool,
        sign: bool,
        verify: bool,
    ) -> jsg::Result<jsg::Rc<act::ActPrivateKey>> {
        act::import_scalar(lock, balance_bits, bytes, extractable, act::Usages { sign, verify })
    }

    #[jsg_method]
    fn act_import_public<'s>(
        &self,
        lock: &mut jsg::Lock<'s>,
        balance_bits: u8,
        bytes: jsg::v8::Local<'s, jsg::v8::Uint8Array>,
    ) -> jsg::Result<jsg::Rc<act::ActPublicKey>> {
        act::import_public(lock, balance_bits, bytes)
    }

    /// `[presentation, continuation]`: the spend message, and the Client's secret spend state
    /// that finalizes the refund.
    #[jsg_method]
    #[expect(clippy::too_many_arguments, reason = "one JavaScript method")]
    fn act_present<'s>(
        &self,
        lock: &mut jsg::Lock<'s>,
        balance_bits: u8,
        credential: jsg::v8::Local<'s, jsg::v8::Uint8Array>,
        ctx_cred: jsg::v8::Local<'s, jsg::v8::Uint8Array>,
        digest: jsg::v8::Local<'s, jsg::v8::Uint8Array>,
        amount: jsg::NonCoercible<u64>,
        allowance: jsg::NonCoercible<u64>,
    ) -> jsg::Result<Vec<jsg::v8::Local<'s, jsg::v8::Value>>> {
        act::present(lock, balance_bits, credential, ctx_cred, digest, *amount, *allowance)
    }
}

type Bytes<'s> = jsg::v8::Local<'s, jsg::v8::Uint8Array>;

/// Contexts carry a 16-bit length prefix in both schemes.
const MAX_CONTEXT: usize = 0xffff;
/// Above every message of the supported shapes (Anchor Sets of up to 1024 keys, balances of up
/// to 64 bits); each decoder then requires its exact length.
const MAX_MESSAGE: usize = 0x10000;

/// Checks a byte argument before anything reads or copies it: at most `max` bytes, and not in a
/// `SharedArrayBuffer`, whose contents can change while they are read.
fn checked<'s>(lock: &mut jsg::Lock<'s>, bytes: Bytes<'s>, max: usize) -> jsg::Result<Bytes<'s>> {
    if bytes.byte_length() > max {
        return Err(data_error("A byte argument is too long."));
    }
    let view: jsg::v8::Local<'s, jsg::v8::ArrayBufferView> = bytes.into();
    if view.buffer(lock).is_shared() {
        return Err(jsg::Error::new_type_error("A byte argument must not be shared."));
    }
    Ok(bytes)
}

/// The challenge digest of both schemes: 32 bytes, the SHA-256 of the canonical challenge.
fn digest_bytes(digest: &[u8]) -> jsg::Result<&[u8]> {
    if digest.len() == 32 {
        Ok(digest)
    } else {
        Err(data_error("The challenge digest must be 32 bytes."))
    }
}

fn data_error(message: &str) -> jsg::Error {
    jsg::Error::new_dom_exception("DataError", message)
}

fn operation_error(message: &str) -> jsg::Error {
    jsg::Error::new_dom_exception("OperationError", message)
}
