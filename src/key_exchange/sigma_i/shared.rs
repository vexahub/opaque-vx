// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed
// licenses.

use derive_where::derive_where;
use digest::{Output, OutputSizeUser};
use generic_array::{ArrayLength, GenericArray};

use crate::errors::ProtocolError;
use crate::key_exchange::{Deserialize, Serialize};
use crate::serialization::SliceExt;

/// Pre-hash of the message to be verified.
#[derive_where(Clone, Debug, Eq, Hash, PartialEq, Zeroize)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(bound = "")
)]
#[allow(dead_code)]
pub struct PreHash<H: OutputSizeUser>(pub Output<H>);

impl<H: OutputSizeUser> Deserialize for PreHash<H>
where
    H::OutputSize: ArrayLength,
{
    fn deserialize_take(input: &mut &[u8]) -> Result<Self, ProtocolError> {
        Ok(Self(input.take_array("pre-hash")?.into_ha0_4()))
    }
}

impl<H: OutputSizeUser> Serialize for PreHash<H>
where
    H::OutputSize: ArrayLength,
{
    type Len = H::OutputSize;

    fn serialize(&self) -> GenericArray<u8, Self::Len> {
        GenericArray::from_slice(self.0.as_slice()).clone()
    }
}
