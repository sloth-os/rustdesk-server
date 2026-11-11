//! Smoke client for the rendezvous TCP key exchange against a running hbbs.
//!
//! Mirrors the desktop client's `key_exchange`: reads the server's signed offer,
//! verifies it against the server's public key, answers with a sealed key, then
//! round-trips an encrypted TestNatRequest to prove both directions' counters
//! and subkeys line up.
//!
//! ```text
//! kx_smoke <rendezvous addr> <server public key, base64>
//! ```

use hbb_common::{
    anyhow::{anyhow, Context},
    bail,
    bytes::Bytes,
    protobuf::Message,
    rendezvous_proto::*,
    sodiumoxide::crypto::{box_, secretbox, sign},
    tcp::{kx_version_for, FramedStream, KxTranscript, KX_PARAMS_DOMAIN},
    ResultType,
};

fn main() -> ResultType<()> {
    hbb_common::tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(run())
}

async fn run() -> ResultType<()> {
    let addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:21116".to_owned());
    let key_b64 = std::env::args()
        .nth(2)
        .ok_or_else(|| anyhow!("usage: kx_smoke <rendezvous addr> <server public key, base64>"))?;
    let pk_bytes = base64::decode(&key_b64).map_err(|e| anyhow!("bad public key: {e}"))?;
    let pk_arr: [u8; 32] = pk_bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("public key is {} bytes, not 32", pk_bytes.len()))?;
    let rs_pk = sign::PublicKey(pk_arr);

    let mut conn = FramedStream::new(&addr, None, 10_000)
        .await
        .context("connect")?;

    // The offer arrives as the first frame on every TCP connection to a keyed server.
    let offer = conn
        .next()
        .await
        .ok_or_else(|| anyhow!("connection closed before the key exchange offer"))?
        .context("read offer")?;
    let msg = RendezvousMessage::parse_from_bytes(&offer).context("parse offer")?;
    let ex = match msg.union {
        Some(rendezvous_message::Union::KeyExchange(ex)) => ex,
        _ => bail!("first frame was not a key exchange offer"),
    };
    if ex.keys.len() != 1 {
        bail!("offer carries {} keys", ex.keys.len());
    }
    let signed =
        sign::verify(&ex.keys[0], &rs_pk).map_err(|_| anyhow!("offer signature mismatch"))?;
    let their_pk_b: [u8; 32] = signed
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("ephemeral public key is {} bytes, not 32", signed.len()))?;

    // The high bit marks a server that signs its parameters; verify them when present.
    if their_pk_b[31] & 0x80 != 0 || !ex.signed_params.is_empty() {
        let params = sign::verify(&ex.signed_params, &rs_pk)
            .ok()
            .and_then(|signed| {
                let params = signed.strip_prefix(KX_PARAMS_DOMAIN)?;
                KxParams::parse_from_bytes(params).ok()
            })
            .ok_or_else(|| anyhow!("missing or invalid signed key exchange parameters"))?;
        if params.pk[..] != their_pk_b[..] || params.version != ex.version {
            bail!("key exchange version or public key does not match its signature");
        }
    }
    println!("offer verified: advertised version {}", ex.version);

    // Answer as the client does: a fresh X25519 keypair, and a fresh secretbox key
    // sealed to the server's ephemeral key under a zero nonce.
    let (our_pk_b, out_sk_b) = box_::gen_keypair();
    let key = secretbox::gen_key();
    let nonce = box_::Nonce([0u8; box_::NONCEBYTES]);
    let sealed_key = box_::seal(&key.0, &nonce, &box_::PublicKey(their_pk_b), &out_sk_b);
    let asymmetric_value = Bytes::from(our_pk_b.0.to_vec());
    let picked = kx_version_for(ex.version);
    let mut reply = RendezvousMessage::new();
    reply.set_key_exchange(KeyExchange {
        keys: vec![asymmetric_value.clone(), Bytes::from(sealed_key)],
        version: picked,
        ..Default::default()
    });
    conn.send(&reply).await.context("send reply")?;
    conn.set_key_split(
        key,
        true,
        &KxTranscript {
            initiator_pk: &asymmetric_value,
            responder_pk: &their_pk_b,
            advertised: ex.version,
            picked,
        },
    )
    .context("install split keys")?;
    if picked == 0 {
        bail!("server advertised version 0; the split-key path was not exercised");
    }
    println!("handshake complete: picked version {picked}");

    // Both directions are now under the split keys: this request leaves encrypted
    // and the response comes back encrypted, each under its own counter.
    let mut probe = RendezvousMessage::new();
    probe.set_test_nat_request(TestNatRequest {
        serial: 0,
        ..Default::default()
    });
    conn.send(&probe).await.context("send encrypted probe")?;
    let bytes = conn
        .next_timeout(10_000)
        .await
        .ok_or_else(|| anyhow!("no reply to the encrypted probe"))?
        .context("read encrypted reply")?;
    let msg = RendezvousMessage::parse_from_bytes(&bytes).context("parse reply")?;
    match msg.union {
        Some(rendezvous_message::Union::TestNatResponse(res)) => {
            println!(
                "encrypted round-trip ok: test_nat_response port {}",
                res.port
            );
        }
        other => bail!("unexpected reply to the probe: {other:?}"),
    }
    Ok(())
}
