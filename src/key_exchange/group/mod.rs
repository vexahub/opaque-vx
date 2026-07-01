// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) VexaHub and contributors.
// Copyright (c) Meta Platforms, Inc. and affiliates.

//! Includes the [`Group`] trait and definitions for the key exchange groups

#[cfg(feature = "curve25519")]
pub mod curve25519;
#[cfg(feature = "ed25519")]
pub mod ed25519;
pub mod elliptic_curve;
#[cfg(feature = "ristretto255")]
pub mod ristretto255;

use generic_array::{ArrayLength, GenericArray};
use hybrid_array::ArraySize;
use rand::{CryptoRng, Rng};
use zeroize::ZeroizeOnDrop;

use crate::errors::{InternalError, ProtocolError};

const STR_OPAQUE_DERIVE_AUTH_KEY_PAIR: [u8; 33] = *b"OPAQUE-DeriveDiffieHellmanKeyPair";

/// A group representation for use in the key exchange
pub trait Group {
    /// Public key
    type Pk: Clone;
    /// Length of the public key
    type PkLen: ArrayLength + ArraySize;
    /// Secret key
    type Sk: Clone + ZeroizeOnDrop;
    /// Length of the secret key
    type SkLen: ArrayLength + ArraySize;

    /// Serializes `self`
    fn serialize_pk(pk: &Self::Pk) -> GenericArray<u8, Self::PkLen>;

    /// Return a public key from its fixed-length bytes representation
    ///
    /// The deserialized bytes must be taken from `bytes`.
    fn deserialize_take_pk(bytes: &mut &[u8]) -> Result<Self::Pk, ProtocolError>;

    /// Generate a random secret key
    fn random_sk<R: Rng + CryptoRng>(rng: &mut R) -> Self::Sk;

    /// Deterministically derive a [`Self::Sk`] from `seed`.
    fn derive_scalar(seed: GenericArray<u8, Self::SkLen>) -> Result<Self::Sk, InternalError>;

    /// Return a public key from its secret key
    fn public_key(sk: &Self::Sk) -> Self::Pk;

    /// Serializes `self`
    fn serialize_sk(sk: &Self::Sk) -> GenericArray<u8, Self::SkLen>;

    /// Return a public key from its fixed-length bytes representation
    ///
    /// The deserialized bytes must be taken from `bytes`.
    fn deserialize_take_sk(bytes: &mut &[u8]) -> Result<Self::Sk, ProtocolError>;
}
