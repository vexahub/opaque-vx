// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) VexaHub and contributors.
// Copyright (c) Meta Platforms, Inc. and affiliates.

//! Defines the [`CipherSuite`] trait to specify the underlying primitives for
//! OPAQUE

use core::ops::Add;

use digest::block_api::{CoreProxy, EagerHash, SmallBlockSizeUser};
use generic_array::ArrayLength;
use generic_array::typenum::{IsLess, Le, NonZero, Sum, U256};

use crate::envelope::NonceLen;
use crate::hash::{Hash, OutputSize, ProxyHash};
use crate::key_exchange::KeyExchange;
use crate::key_exchange::group::Group;
use crate::ksf::Ksf;
use crate::opaque::MaskedResponseLen;

/// Configures the underlying primitives used in OPAQUE
/// * `OprfCs`: A VOPRF ciphersuite, see [`voprf::CipherSuite`].
/// * `KeGroup`: A `Group` used for the `KeyExchange`.
/// * `KeyExchange`: The key exchange protocol to use in the login step
/// * `Hash`: The main hashing function to use
/// * `Ksf`: A key stretching function, typically used for password hashing
pub trait CipherSuite
where
    OprfHash<Self>: Hash + EagerHash,
    <OprfHash<Self> as CoreProxy>::Core: ProxyHash,
    <<OprfHash<Self> as CoreProxy>::Core as SmallBlockSizeUser>::_BlockSize: IsLess<U256>,
    Le<<<OprfHash<Self> as CoreProxy>::Core as SmallBlockSizeUser>::_BlockSize, U256>: NonZero,
    // Envelope: Nonce + Hash
    // MaskedResponse: (Nonce + Hash) + KePk
    // TODO: migrate fully to after hybrid-array v0.5 releases
    // https://github.com/RustCrypto/hybrid-array/issues/66
    OutputSize<OprfHash<Self>>: Add<NonceLen> + ArrayLength,
    Sum<OutputSize<OprfHash<Self>>, NonceLen>: ArrayLength + Add<<KeGroup<Self> as Group>::PkLen>,
    MaskedResponseLen<Self>: ArrayLength,
    // hybrid-array interop bounds
    <OprfGroup<Self> as voprf::Group>::ScalarLen: ArrayLength,
    <OprfGroup<Self> as voprf::Group>::ElemLen: ArrayLength,
{
    /// A VOPRF ciphersuite, see [`voprf::CipherSuite`].
    type OprfCs: voprf::CipherSuite;
    /// A key exchange protocol
    type KeyExchange: KeyExchange;
    /// A key stretching function, typically used for password hashing
    type Ksf: Ksf;
}

pub(crate) type OprfGroup<CS: CipherSuite> = <CS::OprfCs as voprf::CipherSuite>::Group;
pub(crate) type OprfHash<CS: CipherSuite> = <CS::OprfCs as voprf::CipherSuite>::Hash;
pub(crate) type KeGroup<CS: CipherSuite> = <CS::KeyExchange as KeyExchange>::Group;
pub(crate) type KeHash<CS: CipherSuite> = <CS::KeyExchange as KeyExchange>::Hash;
