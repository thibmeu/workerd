// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

//! EC-IHAT (`EC-IHATv1-P256-SHA256`): the Anchor's commit and respond, and the Moderator's
//! redemption verification.

use std::cell::RefCell;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

use ec_ihat::Backend as _;
use jsg::ToJsArrayBuffer;
use jsg::ToJsTypedArray;
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


/// Bounds the work a caller-supplied Anchor Set costs; the draft fixes no limit. Only sets of 16
/// have been benchmarked.
const MAX_ANCHORS: usize = 1024;

/// Tells keys apart, so that a continuation answers only through the key that committed it.
static NEXT_KEY_ID: AtomicU64 = AtomicU64::new(0);

fn ihat_error(error: ec_ihat::Error) -> jsg::Error {
    match error {
        ec_ihat::Error::Deserialize | ec_ihat::Error::InvalidInput => data_error(&error.to_string()),
        _ => operation_error(&error.to_string()),
    }
}

/// An Anchor's private key. The seed, its only encoding, is kept only if the key is extractable.
#[jsg_resource(custom_trace)]
pub struct IhatPrivateKey {
    key: ec_ihat::SecretKey,
    seed: Option<Zeroizing<[u8; ec_ihat::SEED_LENGTH]>>,
    id: u64,
}
jsg::jsg_traced!(IhatPrivateKey);

pub fn generate(lock: &mut jsg::Lock, extractable: bool) -> jsg::Result<jsg::Rc<IhatPrivateKey>> {
    let seed = ec_ihat::DefaultBackend::generate_seed().map_err(ihat_error)?;
    from_seed(lock, seed, extractable)
}

pub fn import_seed<'s>(
    lock: &mut jsg::Lock<'s>,
    seed: Bytes<'s>,
    extractable: bool,
) -> jsg::Result<jsg::Rc<IhatPrivateKey>> {
    let seed = checked(lock, seed, ec_ihat::SEED_LENGTH)?;
    let seed = Zeroizing::new(
        <[u8; ec_ihat::SEED_LENGTH]>::try_from(seed.as_slice(lock))
            .map_err(|_| data_error("An EC-IHAT seed is 48 bytes."))?,
    );
    from_seed(lock, seed, extractable)
}

fn from_seed(
    lock: &mut jsg::Lock,
    seed: Zeroizing<[u8; ec_ihat::SEED_LENGTH]>,
    extractable: bool,
) -> jsg::Result<jsg::Rc<IhatPrivateKey>> {
    let key = ec_ihat::SecretKey::from_seed(&seed).map_err(ihat_error)?;
    let id = NEXT_KEY_ID.fetch_add(1, Ordering::Relaxed);
    let seed = extractable.then_some(seed);
    Ok(jsg::Rc::new(lock, IhatPrivateKey { key, seed, id }))
}

#[jsg_resource]
impl IhatPrivateKey {
    #[jsg_method]
    fn public_key(&self, lock: &mut jsg::Lock) -> jsg::Rc<IhatPublicKey> {
        jsg::Rc::new(lock, IhatPublicKey { key: self.key.public_key() })
    }

    #[jsg_method]
    fn export_seed<'s>(&self, lock: &mut jsg::Lock<'s>) -> jsg::Result<v8::Local<'s, v8::ArrayBuffer>> {
        let seed = self
            .seed
            .as_ref()
            .ok_or_else(|| jsg::Error::new_dom_exception("InvalidAccessError", "The key is not extractable."))?;
        Ok(seed.to_js_array_buffer(lock))
    }

    /// `Commit(ctx_iss)`. The state stays native, in the returned continuation.
    #[jsg_method]
    fn commit<'s>(&self, lock: &mut jsg::Lock<'s>, ctx_iss: Bytes<'s>) -> jsg::Result<jsg::Rc<IhatContinuation>> {
        let ctx_iss = checked(lock, ctx_iss, MAX_CONTEXT)?.as_slice(lock).to_vec();
        let (state, message) = ec_ihat::commit(&ctx_iss).map_err(ihat_error)?;
        Ok(jsg::Rc::new(
            lock,
            IhatContinuation {
                key_id: self.id,
                ctx_iss,
                commitment: message.to_bytes(),
                state: RefCell::new(Some(state)),
            },
        ))
    }

    /// `Respond(skA, state, challenge)`. Consumes the continuation's state first, whatever the
    /// outcome: a second response from one state discloses the key.
    #[jsg_method]
    fn respond<'s>(
        &self,
        lock: &mut jsg::Lock<'s>,
        continuation: jsg::Rc<IhatContinuation>,
        ctx_iss: Bytes<'s>,
        challenge: Bytes<'s>,
    ) -> jsg::Result<v8::Local<'s, v8::ArrayBuffer>> {
        // Checked before the state is taken: a call that cannot be read consumes nothing.
        let ctx_iss = checked(lock, ctx_iss, MAX_CONTEXT)?;
        let challenge = checked(lock, challenge, MAX_MESSAGE)?;
        let state = continuation
            .state
            .borrow_mut()
            .take()
            .ok_or_else(|| operation_error("The continuation was already used."))?;
        if continuation.key_id != self.id || continuation.ctx_iss != ctx_iss.as_slice(lock) {
            return Err(operation_error("The continuation belongs to another key or issuance context."));
        }
        let challenge = ec_ihat::ChallengeMessage::from_bytes(challenge.as_slice(lock)).map_err(ihat_error)?;
        let response = ec_ihat::respond(&self.key, state, &challenge).map_err(ihat_error)?;
        Ok(response.to_bytes().to_js_array_buffer(lock))
    }
}

/// An Anchor's state between commit and respond. It cannot be exported, imported or cloned, and
/// answers at most one challenge.
// shortcut: lives only in this isolate's memory, so a commit and its respond must run in the same
// isolate; a durable flow needs authenticated, consume-once import/export, which is unimplemented.
#[jsg_resource(custom_trace)]
pub struct IhatContinuation {
    key_id: u64,
    ctx_iss: Vec<u8>,
    commitment: [u8; 66],
    state: RefCell<Option<ec_ihat::AnchorState>>,
}
jsg::jsg_traced!(IhatContinuation);

#[jsg_resource]
impl IhatContinuation {
    /// The `CommitMessage`.
    #[jsg_method]
    fn commitment<'s>(&self, lock: &mut jsg::Lock<'s>) -> v8::Local<'s, v8::Uint8Array> {
        self.commitment.to_js_typed_array(lock)
    }
}

/// An Anchor's public key.
#[jsg_resource(custom_trace)]
pub struct IhatPublicKey {
    key: ec_ihat::PublicKey,
}
jsg::jsg_traced!(IhatPublicKey);

pub fn import_public<'s>(lock: &mut jsg::Lock<'s>, bytes: Bytes<'s>) -> jsg::Result<jsg::Rc<IhatPublicKey>> {
    let bytes = checked(lock, bytes, 33)?;
    let bytes = <&[u8; 33]>::try_from(bytes.as_slice(lock))
        .map_err(|_| data_error("An EC-IHAT public key is 33 bytes."))?;
    let key = ec_ihat::PublicKey::from_bytes(bytes).map_err(ihat_error)?;
    Ok(jsg::Rc::new(lock, IhatPublicKey { key }))
}

#[jsg_resource]
impl IhatPublicKey {
    /// Compressed SEC1.
    #[jsg_method]
    fn export<'s>(&self, lock: &mut jsg::Lock<'s>) -> v8::Local<'s, v8::ArrayBuffer> {
        self.key.to_bytes().to_js_array_buffer(lock)
    }
}

/// `VerifyRedemption` over the Anchor Set in its order: whether the redemption is well formed and
/// verifies. The Anchor Set must not repeat a key.
pub fn verify<'s>(
    lock: &mut jsg::Lock<'s>,
    anchors: &[jsg::Rc<IhatPublicKey>],
    redemption: Bytes<'s>,
    ctx_iss: Bytes<'s>,
    ctx_red: Bytes<'s>,
    digest: Bytes<'s>,
) -> jsg::Result<bool> {
    if anchors.is_empty() || anchors.len() > MAX_ANCHORS {
        return Err(data_error("The Anchor Set must hold 1 to 1024 keys."));
    }
    // ihat-rs does not reject a repeated key, which would weaken issuer hiding.
    let mut encodings: Vec<_> = anchors.iter().map(|anchor| anchor.key.to_bytes()).collect();
    encodings.sort_unstable();
    if encodings.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(data_error("The Anchor Set repeats a key."));
    }
    let redemption = checked(lock, redemption, MAX_MESSAGE)?;
    let ctx_iss = checked(lock, ctx_iss, MAX_CONTEXT)?;
    let ctx_red = checked(lock, ctx_red, MAX_CONTEXT)?;
    let digest = checked(lock, digest, 32)?;
    digest_bytes(digest.as_slice(lock))?;
    let set: Vec<_> = anchors.iter().map(|anchor| anchor.key.clone()).collect();
    let result = ec_ihat::Redemption::from_bytes(redemption.as_slice(lock), set.len()).and_then(|redemption| {
        ec_ihat::verify_redemption(
            &set,
            &redemption,
            ctx_iss.as_slice(lock),
            ctx_red.as_slice(lock),
            digest.as_slice(lock),
        )
    });
    match result {
        Ok(_) => Ok(true),
        Err(ec_ihat::Error::Verify | ec_ihat::Error::Deserialize) => Ok(false),
        Err(error) => Err(ihat_error(error)),
    }
}
