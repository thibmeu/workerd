// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

//! ACT (`ACTv1-P256-SHA256`): the Moderator's issuance, spend verification and refund, and the
//! Client's presentation.

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

use jsg::ToJsArrayBuffer;
use jsg::v8;
use jsg_macros::jsg_method;
use jsg_macros::jsg_resource;
use zeroize::Zeroizing;

use crate::Bytes;
use crate::MAX_CONTEXT;
use crate::MAX_MESSAGE;
use crate::checked;
use crate::data_error;
use crate::digest_bytes;
use crate::operation_error;

type Values<'s> = Vec<v8::Local<'s, v8::Value>>;

fn act_error(error: act::Error) -> jsg::Error {
    match error {
        act::Error::Deserialize | act::Error::Amount | act::Error::InvalidInput => {
            data_error(&error.to_string())
        }
        _ => operation_error(&error.to_string()),
    }
}

thread_local! {
    // Public, deterministic in the balance width, and costly to build: built once per thread.
    static PARAMS: RefCell<HashMap<u8, Rc<act::Params>>> = RefCell::new(HashMap::new());
}

fn params(balance_bits: u8) -> jsg::Result<Rc<act::Params>> {
    if let Some(params) = PARAMS.with_borrow(|cache| cache.get(&balance_bits).cloned()) {
        return Ok(params);
    }
    let params = Rc::new(act::Params::new(balance_bits).map_err(act_error)?);
    PARAMS.with_borrow_mut(|cache| cache.insert(balance_bits, Rc::clone(&params)));
    Ok(params)
}

/// A Moderator's private key, with the parameters of its balance width. Its extractability and
/// usages are enforced here, not only in mole.ts, whose checks run on builtins that the Worker's
/// code can replace.
#[jsg_resource(custom_trace)]
pub struct ActPrivateKey {
    params: Rc<act::Params>,
    key: act::SecretKey,
    extractable: bool,
    usages: Usages,
}

/// The WebCrypto usages of a private key.
#[derive(Clone, Copy)]
pub struct Usages {
    pub sign: bool,
    pub verify: bool,
}

impl ActPrivateKey {
    fn require(&self, sign: bool, verify: bool) -> jsg::Result<()> {
        if (sign && !self.usages.sign) || (verify && !self.usages.verify) {
            return Err(jsg::Error::new_dom_exception("InvalidAccessError", "The key does not have this usage."));
        }
        Ok(())
    }
}
jsg::jsg_traced!(ActPrivateKey);

pub fn generate(
    lock: &mut jsg::Lock,
    balance_bits: u8,
    extractable: bool,
    usages: Usages,
) -> jsg::Result<jsg::Rc<ActPrivateKey>> {
    let params = params(balance_bits)?;
    let key = act::SecretKey::generate().map_err(act_error)?;
    Ok(jsg::Rc::new(lock, ActPrivateKey { params, key, extractable, usages }))
}

pub fn import_scalar<'s>(
    lock: &mut jsg::Lock<'s>,
    balance_bits: u8,
    bytes: Bytes<'s>,
    extractable: bool,
    usages: Usages,
) -> jsg::Result<jsg::Rc<ActPrivateKey>> {
    let params = params(balance_bits)?;
    let bytes = checked(lock, bytes, 32)?;
    let scalar = Zeroizing::new(
        <[u8; 32]>::try_from(bytes.as_slice(lock)).map_err(|_| data_error("An ACT private key is 32 bytes."))?,
    );
    let key = act::SecretKey::from_bytes(&scalar).map_err(act_error)?;
    Ok(jsg::Rc::new(lock, ActPrivateKey { params, key, extractable, usages }))
}

#[jsg_resource]
impl ActPrivateKey {
    #[jsg_method]
    fn public_key(&self, lock: &mut jsg::Lock) -> jsg::Rc<ActPublicKey> {
        let params = Rc::clone(&self.params);
        jsg::Rc::new(lock, ActPublicKey { params, key: self.key.public_key() })
    }

    /// The secret scalar, big-endian.
    #[jsg_method]
    fn export_scalar<'s>(&self, lock: &mut jsg::Lock<'s>) -> jsg::Result<v8::Local<'s, v8::ArrayBuffer>> {
        if !self.extractable {
            return Err(jsg::Error::new_dom_exception("InvalidAccessError", "The key is not extractable."));
        }
        Ok(Zeroizing::new(self.key.to_bytes()).to_js_array_buffer(lock))
    }

    /// `IssueResponse`: verifies the request, then signs a Credential of balance `amount`.
    #[jsg_method]
    fn issue<'s>(
        &self,
        lock: &mut jsg::Lock<'s>,
        request: Bytes<'s>,
        ctx_cred: Bytes<'s>,
        amount: jsg::NonCoercible<u64>,
    ) -> jsg::Result<v8::Local<'s, v8::ArrayBuffer>> {
        self.require(true, false)?;
        let request = checked(lock, request, MAX_MESSAGE)?;
        let ctx_cred = checked(lock, ctx_cred, MAX_CONTEXT)?;
        let request = act::IssueRequestMessage::from_bytes(&self.params, request.as_slice(lock)).map_err(act_error)?;
        let verified = act::verify_issue_request(&self.params, &request).map_err(act_error)?;
        let response =
            act::issue_response(&self.key, ctx_cred.as_slice(lock), *amount, verified).map_err(act_error)?;
        Ok(response.to_bytes().to_js_array_buffer(lock))
    }

    /// `VerifySpend` of a spend of `cost` with allowance `allowance`: whether the spend is well
    /// formed, has those amounts, and verifies. The caller still checks the nullifier against its
    /// record.
    #[jsg_method]
    fn verify_spend<'s>(
        &self,
        lock: &mut jsg::Lock<'s>,
        spend: Bytes<'s>,
        ctx_cred: Bytes<'s>,
        digest: Bytes<'s>,
        cost: jsg::NonCoercible<u64>,
        allowance: jsg::NonCoercible<u64>,
    ) -> jsg::Result<bool> {
        self.require(false, true)?;
        let spend = checked(lock, spend, MAX_MESSAGE)?;
        let ctx_cred = checked(lock, ctx_cred, MAX_CONTEXT)?;
        let digest = checked(lock, digest, 32)?;
        digest_bytes(digest.as_slice(lock))?;
        let spend = match self.spend(lock, spend, *cost, *allowance) {
            Ok(spend) => spend,
            Err(act::Error::Deserialize | act::Error::Verify) => return Ok(false),
            Err(error) => return Err(act_error(error)),
        };
        match act::verify_spend(&self.params, &self.key, ctx_cred.as_slice(lock), digest.as_slice(lock), &spend) {
            Ok(_) => Ok(true),
            Err(act::Error::Verify | act::Error::Deserialize) => Ok(false),
            Err(error) => Err(act_error(error)),
        }
    }

    /// `VerifySpend` then `IssueRefund` of `refund` credits: checks that the spend has amounts
    /// `cost` and `allowance` before anything else, verifies it once, and signs only if it
    /// verifies. The caller records the spend's nullifier before releasing the refund.
    #[jsg_method]
    #[expect(clippy::too_many_arguments, reason = "one JavaScript method")]
    fn refund<'s>(
        &self,
        lock: &mut jsg::Lock<'s>,
        spend: Bytes<'s>,
        ctx_cred: Bytes<'s>,
        digest: Bytes<'s>,
        cost: jsg::NonCoercible<u64>,
        allowance: jsg::NonCoercible<u64>,
        refund: jsg::NonCoercible<u64>,
    ) -> jsg::Result<v8::Local<'s, v8::ArrayBuffer>> {
        self.require(true, true)?;
        let spend = checked(lock, spend, MAX_MESSAGE)?;
        let ctx_cred = checked(lock, ctx_cred, MAX_CONTEXT)?;
        let digest = checked(lock, digest, 32)?;
        let digest = digest_bytes(digest.as_slice(lock))?;
        let spend = self.spend(lock, spend, *cost, *allowance).map_err(act_error)?;
        let verified =
            act::verify_spend(&self.params, &self.key, ctx_cred.as_slice(lock), digest, &spend).map_err(act_error)?;
        let message = act::issue_refund(verified, *refund).map_err(act_error)?.to_bytes();
        Ok(message.to_js_array_buffer(lock))
    }
}

impl ActPrivateKey {
    /// Decodes a spend, requiring the amounts the caller's policy expects (`Verify` otherwise).
    fn spend<'s>(
        &self,
        lock: &jsg::Lock<'s>,
        spend: Bytes<'s>,
        cost: u64,
        allowance: u64,
    ) -> Result<act::SpendMessage, act::Error> {
        if cost > self.params.max_amount() || allowance > self.params.max_amount() {
            return Err(act::Error::Amount);
        }
        let spend = act::SpendMessage::from_bytes(&self.params, spend.as_slice(lock))?;
        if spend.amount() == cost && spend.allowance() == allowance {
            Ok(spend)
        } else {
            Err(act::Error::Verify)
        }
    }
}

/// A Moderator's public key.
#[jsg_resource(custom_trace)]
pub struct ActPublicKey {
    params: Rc<act::Params>,
    key: act::PublicKey,
}
jsg::jsg_traced!(ActPublicKey);

pub fn import_public<'s>(
    lock: &mut jsg::Lock<'s>,
    balance_bits: u8,
    bytes: Bytes<'s>,
) -> jsg::Result<jsg::Rc<ActPublicKey>> {
    let params = params(balance_bits)?;
    let bytes = checked(lock, bytes, 33)?;
    let bytes =
        <&[u8; 33]>::try_from(bytes.as_slice(lock)).map_err(|_| data_error("An ACT public key is 33 bytes."))?;
    let key = act::PublicKey::from_bytes(bytes).map_err(act_error)?;
    Ok(jsg::Rc::new(lock, ActPublicKey { params, key }))
}

#[jsg_resource]
impl ActPublicKey {
    /// Compressed SEC1.
    #[jsg_method]
    fn export<'s>(&self, lock: &mut jsg::Lock<'s>) -> v8::Local<'s, v8::ArrayBuffer> {
        self.key.to_bytes().to_js_array_buffer(lock)
    }

    #[jsg_method]
    fn balance_bits(&self) -> u8 {
        self.params.balance_width()
    }
}

/// `ProveSpend` from a Credential's bytes: `[presentation, continuation]`.
pub fn present<'s>(
    lock: &mut jsg::Lock<'s>,
    balance_bits: u8,
    credential: Bytes<'s>,
    ctx_cred: Bytes<'s>,
    digest: Bytes<'s>,
    amount: u64,
    allowance: u64,
) -> jsg::Result<Values<'s>> {
    let params = params(balance_bits)?;
    let credential = checked(lock, credential, MAX_MESSAGE)?;
    let ctx_cred = checked(lock, ctx_cred, MAX_CONTEXT)?;
    let digest = checked(lock, digest, 32)?;
    let digest = digest_bytes(digest.as_slice(lock))?;
    let credential = act::Credential::from_bytes(&params, credential.as_slice(lock)).map_err(act_error)?;
    let (state, spend) = act::prove_spend(&params, credential, ctx_cred.as_slice(lock), amount, allowance, digest)
        .map_err(act_error)?;
    let state = state.to_bytes();
    Ok(vec![spend.to_bytes().to_js_array_buffer(lock).into(), state.to_js_array_buffer(lock).into()])
}
