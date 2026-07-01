// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed
// licenses.

//! Implementation for EC curves via [`elliptic_curve`] traits.

use core::ops::Mul;
use digest::OutputSizeUser;
use digest::block_api::BlockSizeUser;
use elliptic_curve::group::GroupEncoding;
use elliptic_curve::point::NonIdentity;
use elliptic_curve::sec1::{ModulusSize, ToSec1Point};
use elliptic_curve::{
    CurveArithmetic, FieldBytesSize, Generate, NonZeroScalar, ProjectivePoint, Scalar, SecretKey,
};
use generic_array::typenum::{IsGreaterOrEqual, IsLess, IsLessOrEqual, Prod, True, U2, U256};
use generic_array::{ArrayLength, GenericArray};
use rand::{CryptoRng, Rng};
use voprf::Mode;

use super::{Group, STR_OPAQUE_DERIVE_AUTH_KEY_PAIR};
use crate::errors::{InternalError, ProtocolError};
use crate::key_exchange::shared::DiffieHellman;
use crate::serialization::SliceExt;

impl<G> Group for G
where
    Self: CurveArithmetic + voprf::CipherSuite<Group = Self> + voprf::Group<Scalar = Scalar<Self>>,
    FieldBytesSize<Self>: ModulusSize + ArrayLength,
    <FieldBytesSize<Self> as ModulusSize>::CompressedPointSize: ArrayLength,
    ProjectivePoint<Self>: GroupEncoding<
            Repr = hybrid_array::Array<
                u8,
                <FieldBytesSize<Self> as ModulusSize>::CompressedPointSize,
            >,
        > + ToSec1Point<Self>,
    // Bounds required by voprf::CipherSuite
    <Self as voprf::Group>::SecurityLevel: Mul<U2>,
    <<Self as voprf::CipherSuite>::Hash as OutputSizeUser>::OutputSize: ArrayLength
        + IsLess<U256>
        + IsLessOrEqual<
            <<Self as voprf::CipherSuite>::Hash as BlockSizeUser>::BlockSize,
            Output = True,
        > + IsGreaterOrEqual<Prod<<Self as voprf::Group>::SecurityLevel, U2>, Output = True>,
{
    // We don't use `elliptic_curve::PublicKey` because it stores its internals in a
    // format ideal for serialization and not computation. This is inconsistent with
    // our other implementations.
    type Pk = NonIdentity<ProjectivePoint<Self>>;

    type PkLen = <FieldBytesSize<Self> as ModulusSize>::CompressedPointSize;

    type Sk = SecretKey<Self>;

    type SkLen = FieldBytesSize<Self>;

    fn serialize_pk(pk: &Self::Pk) -> GenericArray<u8, Self::PkLen> {
        GenericArray::from_slice(pk.to_sec1_point(true).as_bytes()).clone()
    }

    fn deserialize_take_pk(bytes: &mut &[u8]) -> Result<Self::Pk, ProtocolError> {
        NonIdentity::<ProjectivePoint<Self>>::from_bytes(
            &bytes.take_array("public key")?.into_ha0_4(),
        )
        .into_option()
        .ok_or(ProtocolError::SerializationError)
    }

    fn random_sk<R: Rng + CryptoRng>(rng: &mut R) -> Self::Sk {
        SecretKey::<Self>::generate_from_rng(rng)
    }

    fn derive_scalar(seed: GenericArray<u8, Self::SkLen>) -> Result<Self::Sk, InternalError> {
        voprf::derive_key::<Self>(&seed, &STR_OPAQUE_DERIVE_AUTH_KEY_PAIR, Mode::Oprf)
            .map(|scalar| {
                NonZeroScalar::new(scalar).expect("`voprf::derive_key()` returned a zero scalar")
            })
            .map(SecretKey::from)
            .map_err(InternalError::from)
    }

    fn public_key(sk: &Self::Sk) -> Self::Pk {
        NonIdentity::<ProjectivePoint<Self>>::mul_by_generator(&sk.to_nonzero_scalar())
    }

    fn serialize_sk(sk: &Self::Sk) -> GenericArray<u8, Self::SkLen> {
        GenericArray::from(sk.to_bytes())
    }

    fn deserialize_take_sk(bytes: &mut &[u8]) -> Result<Self::Sk, ProtocolError> {
        SecretKey::<Self>::from_bytes(&bytes.take_array("secret key")?.into_ha0_4())
            .map_err(|_| ProtocolError::SerializationError)
    }
}

impl<G> DiffieHellman<G> for SecretKey<G>
where
    G: CurveArithmetic + voprf::CipherSuite<Group = G> + voprf::Group<Scalar = Scalar<G>>,
    FieldBytesSize<G>: ModulusSize + ArrayLength,
    <FieldBytesSize<G> as ModulusSize>::CompressedPointSize: ArrayLength,
    ProjectivePoint<G>: GroupEncoding<
            Repr = hybrid_array::Array<u8, <FieldBytesSize<G> as ModulusSize>::CompressedPointSize>,
        > + ToSec1Point<G>,
    <G as voprf::Group>::SecurityLevel: Mul<U2>,
    <<G as voprf::CipherSuite>::Hash as OutputSizeUser>::OutputSize: ArrayLength
        + IsLess<U256>
        + IsLessOrEqual<<<G as voprf::CipherSuite>::Hash as BlockSizeUser>::BlockSize, Output = True>
        + IsGreaterOrEqual<Prod<<G as voprf::Group>::SecurityLevel, U2>, Output = True>,
{
    fn diffie_hellman(
        &self,
        pk: &NonIdentity<ProjectivePoint<G>>,
    ) -> GenericArray<u8, <FieldBytesSize<G> as ModulusSize>::CompressedPointSize> {
        GenericArray::from_slice(
            (pk * self.to_nonzero_scalar())
                .to_sec1_point(true)
                .as_bytes(),
        )
        .clone()
    }
}
