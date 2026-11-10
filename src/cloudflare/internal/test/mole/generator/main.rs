// Fixtures for workerd's cloudflare:mole test and benchmark: L = 16, Anchor Set of 16, the
// contexts of act-rs benches/webcrypto, and 32-byte digests (SHA-256 of its digest string).
use ec_ihat::Backend as _;
use sha2::Digest as _;
const CTX_ISS: &[u8] = b"benchmark-issuance-context";
const CTX_RED: &[u8] = b"benchmark-redemption-context";
const CTX_CRED: &[u8] = b"benchmark-context";
fn h(b: &[u8]) -> String { hex::encode(b) }
fn main() {
    let digest: [u8; 32] = sha2::Sha256::digest(b"benchmark-challenge-digest").into();
    let (l, n) = (16u8, 16usize);
    let seeds: Vec<_> = (0..n).map(|_| *ec_ihat::DefaultBackend::generate_seed().unwrap()).collect();
    let keys: Vec<ec_ihat::SecretKey> = seeds.iter().map(|s| ec_ihat::SecretKey::from_seed(s).unwrap()).collect();
    let anchors: Vec<_> = keys.iter().map(|k| k.public_key()).collect();
    let index = n / 2;
    let (st, cm) = ec_ihat::commit(CTX_ISS).unwrap();
    let (client, msg) = ec_ihat::challenge(&anchors[index], CTX_ISS, CTX_RED, &cm).unwrap();
    let resp = ec_ihat::respond(&keys[index], st, &msg).unwrap();
    let e = ec_ihat::finalize(&anchors[index], client, &resp).unwrap();
    let redemption = ec_ihat::redeem(&anchors, index, e, CTX_ISS, CTX_RED, &digest).unwrap();
    let nullifier = ec_ihat::verify_redemption(&anchors, &redemption, CTX_ISS, CTX_RED, &digest).unwrap();

    let params: act::Params = act::Params::new(l).unwrap();
    let key: act::SecretKey = act::SecretKey::generate().unwrap();
    let (ist, request) = act::issue_request(&params).unwrap();
    let balance = params.max_amount() - 1;
    let response = act::issue_response(&key, CTX_CRED, balance, act::verify_issue_request(&params, &request).unwrap()).unwrap();
    let cred = act::finalize_issue(&params, &key.public_key(), CTX_CRED, ist, &response).unwrap();
    let credential = cred.to_bytes().to_vec();
    let (s, a, t) = (balance / 2, 0, balance / 4); // act-rs benches "spend" shape
    let (_, spend) = act::prove_spend(&params, cred, CTX_CRED, s, a, &digest).unwrap();
    act::verify_spend(&params, &key, CTX_CRED, &digest, &spend).unwrap();
    println!("{{\n  \"generator\": \"act-rs f1bd64b, ihat-rs ed75614 (rustcrypto backend)\",");
    println!("  \"balanceBits\": {l},\n  \"issuanceContext\": \"{}\",\n  \"redemptionContext\": \"{}\",\n  \"credentialContext\": \"{}\",\n  \"challengeDigest\": \"{}\",", h(CTX_ISS), h(CTX_RED), h(CTX_CRED), h(&digest));
    println!("  \"anchorSeeds\": [{}],", seeds.iter().map(|s| format!("\"{}\"", h(s))).collect::<Vec<_>>().join(", "));
    println!("  \"anchorPublicKeys\": [{}],", anchors.iter().map(|p| format!("\"{}\"", h(&p.to_bytes()))).collect::<Vec<_>>().join(", "));
    println!("  \"redemption\": \"{}\",\n  \"redemptionNullifier\": \"{}\",", h(&redemption.to_bytes()), h(&nullifier));
    println!("  \"moderatorScalar\": \"{}\",\n  \"moderatorPublicKey\": \"{}\",", h(&key.to_bytes()), h(&key.public_key().to_bytes()));
    println!("  \"issueRequest\": \"{}\",\n  \"balance\": \"{balance}\",\n  \"credential\": \"{}\",", h(&request.to_bytes()), h(&credential));
    println!("  \"spend\": \"{}\",\n  \"spendNullifier\": \"{}\",\n  \"cost\": \"{s}\",\n  \"allowance\": \"{a}\",\n  \"refund\": \"{t}\"\n}}", h(&spend.to_bytes()), h(&spend.nullifier()));
}
