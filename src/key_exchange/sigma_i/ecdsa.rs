// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed
// licenses.

//! ECDSA implementation for [`elliptic_curve`] [`Group`] implementations to
//! support [`SigmaI`](crate::SigmaI).

use core::marker::PhantomData;

use digest::block_api::{BlockSizeUser, EagerHash};
use digest::{Digest, FixedOutputReset, HashMarker};
use ecdsa::{EcdsaCurve, SignatureSize};
use elliptic_curve::point::NonIdentity;
use elliptic_curve::{CurveArithmetic, FieldBytes, ProjectivePoint, SecretKey};
use generic_array::{ArrayLength, GenericArray};
use hybrid_array::ArraySize;
use rand::{CryptoRng, Rng};

use super::{Message, MessageBuilder, SignatureProtocol};
use crate::ciphersuite::CipherSuite;
use crate::errors::ProtocolError;
use crate::key_exchange::group::Group;
pub use crate::key_exchange::sigma_i::shared::PreHash;
use crate::serialization::SliceExt;

/// ECDSA for [`SigmaI`](crate::SigmaI).
///
/// The ["verification state"](Self::VerifyState) is the pre-hash for the
/// message to be verified.
pub struct Ecdsa<G, H>(PhantomData<(G, H)>);

impl<G, H> SignatureProtocol for Ecdsa<G, H>
where
    G: CurveArithmetic
        + Group<Sk = SecretKey<G>, Pk = NonIdentity<ProjectivePoint<G>>>
        + EcdsaCurve,
    SignatureSize<G>: ArrayLength + ArraySize,
    H: EagerHash + FixedOutputReset + BlockSizeUser + HashMarker + Digest + Clone + Default,
{
    type Group = G;
    type Signature = ecdsa::Signature<G>;
    type SignatureLen = SignatureSize<G>;
    type VerifyState<CS: CipherSuite, KE: Group> = PreHash<H>;

    // We use a manual implementation of `RandomizedPrehashSigner` to use the same
    // hash for the message as for generating `k`. See
    // https://github.com/RustCrypto/signatures/issues/949.
    fn sign<'a, R: CryptoRng + Rng, CS: CipherSuite, KE: Group>(
        sk: &<Self::Group as Group>::Sk,
        rng: &mut R,
        message: &Message<CS, KE>,
    ) -> (Self::Signature, Self::VerifyState<CS, KE>) {
        let hash = message.hash::<H>();

        (
            sign::<_, G, H>(sk, rng, &hash.sign.finalize_fixed()),
            PreHash(hash.verify.finalize_fixed()),
        )
    }

    fn verify<CS: CipherSuite, KE: Group>(
        pk: &<Self::Group as Group>::Pk,
        _: MessageBuilder<'_, CS>,
        state: Self::VerifyState<CS, KE>,
        signature: &Self::Signature,
    ) -> Result<(), ProtocolError> {
        verify(pk, &state.0, signature)
    }

    fn serialize_signature(signature: &Self::Signature) -> GenericArray<u8, Self::SignatureLen> {
        GenericArray::from_slice(signature.to_bytes().as_slice()).clone()
    }

    fn deserialize_take_signature(bytes: &mut &[u8]) -> Result<Self::Signature, ProtocolError> {
        ecdsa::Signature::from_bytes(&bytes.take_array("signature")?.into_ha0_4())
            .map_err(|_| ProtocolError::SerializationError)
    }
}

fn sign<R, C, H>(sk: &SecretKey<C>, rng: &mut R, pre_hash: &[u8]) -> ecdsa::Signature<C>
where
    R: CryptoRng + Rng,
    C: CurveArithmetic + EcdsaCurve,
    SignatureSize<C>: ArraySize,
    H: Digest + BlockSizeUser + FixedOutputReset,
{
    let mut ad = FieldBytes::<C>::default();
    rng.fill_bytes(&mut ad);
    ecdsa::hazmat::sign_prehashed_rfc6979::<C, H>(&sk.to_nonzero_scalar(), pre_hash, &ad).0
}

fn verify<C>(
    pk: &NonIdentity<ProjectivePoint<C>>,
    pre_hash: &[u8],
    signature: &ecdsa::Signature<C>,
) -> Result<(), ProtocolError>
where
    C: CurveArithmetic + EcdsaCurve,
    SignatureSize<C>: ArraySize,
{
    ecdsa::hazmat::verify_prehashed(&pk.to_point(), pre_hash, signature)
        .map_err(|_| ProtocolError::InvalidLoginError)
}

#[test]
fn ecdsa() {
    use std::vec;

    use digest::Digest;
    use ecdsa::signature::hazmat::PrehashVerifier;
    use p256::ecdsa::signature::RandomizedDigestSigner;
    use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
    use p256::{NistP256, PublicKey};
    use rand::rngs::SysRng;
    use rand_core::UnwrapErr;
    use sha2::Sha256;

    use crate::tests::mock_rng::CycleRng;

    let mut rng = CycleRng::new(vec![1; 32]);

    let mut message = [0; 1024];
    UnwrapErr(SysRng).fill_bytes(&mut message);
    let hash = Sha256::new_with_prefix(message);

    let sk = NistP256::random_sk(&mut UnwrapErr(SysRng));
    let signing_key = SigningKey::from(sk.clone());

    let signature: Signature = signing_key.sign_digest_with_rng(&mut rng, |d: &mut Sha256| {
        d.update(message);
    });
    let custom_signature = sign::<_, _, Sha256>(&sk, &mut rng, &hash.clone().finalize());

    assert_eq!(signature, custom_signature);

    let pk = NistP256::public_key(&sk);
    let verifying_key = VerifyingKey::from(PublicKey::from(&pk));

    verifying_key
        .verify_prehash(&hash.clone().finalize(), &signature)
        .unwrap();
    verify(&pk, &hash.finalize(), &custom_signature).unwrap();
}
