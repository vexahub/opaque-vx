// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed
// licenses.

//! A convenience trait for digest bounds used throughout the library

use digest::block_api::{
    BlockSizeUser, BufferKindUser, CoreProxy, FixedOutputCore, SmallBlockSizeUser,
};
use digest::block_buffer::Eager;
use digest::{Digest, FixedOutputReset, HashMarker, OutputSizeUser};
use generic_array::typenum::{IsLess, Le, NonZero, U256};

pub(crate) type OutputSize<H> = <<H as CoreProxy>::Core as OutputSizeUser>::OutputSize;

/// Trait to simplify requirements for [`Hash`].
pub trait ProxyHash:
    HashMarker + FixedOutputCore + BufferKindUser<BufferKind = Eager> + OutputSizeUser + Default + Clone
where
    <Self as SmallBlockSizeUser>::_BlockSize: IsLess<U256>,
    Le<<Self as SmallBlockSizeUser>::_BlockSize, U256>: NonZero,
{
}

impl<
    T: HashMarker
        + FixedOutputCore
        + BufferKindUser<BufferKind = Eager>
        + OutputSizeUser
        + Default
        + Clone,
> ProxyHash for T
where
    <T as SmallBlockSizeUser>::_BlockSize: IsLess<U256>,
    Le<<T as SmallBlockSizeUser>::_BlockSize, U256>: NonZero,
{
}

/// Trait inheriting the requirements from [`Digest`] for compatibility
/// with HKDF and HMAC Associated types could be simplified when they are made
/// as defaults: <https://github.com/rust-lang/rust/issues/29661>
pub trait Hash:
    Default
    + HashMarker
    + Digest
    + OutputSizeUser<OutputSize = OutputSize<Self>>
    + BlockSizeUser
    + FixedOutputReset
    + CoreProxy
    + Clone
where
    <Self as CoreProxy>::Core: ProxyHash,
    <<Self as CoreProxy>::Core as SmallBlockSizeUser>::_BlockSize: IsLess<U256>,
    Le<<<Self as CoreProxy>::Core as SmallBlockSizeUser>::_BlockSize, U256>: NonZero,
    OutputSize<Self>: generic_array::ArrayLength,
{
}

impl<
    T: Default
        + HashMarker
        + Digest
        + OutputSizeUser<OutputSize = OutputSize<Self>>
        + BlockSizeUser
        + FixedOutputReset
        + CoreProxy
        + Clone,
> Hash for T
where
    <T as CoreProxy>::Core: ProxyHash,
    <<T as CoreProxy>::Core as SmallBlockSizeUser>::_BlockSize: IsLess<U256>,
    Le<<<T as CoreProxy>::Core as SmallBlockSizeUser>::_BlockSize, U256>: NonZero,
    OutputSize<T>: generic_array::ArrayLength,
{
}
