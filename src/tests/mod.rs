// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) VexaHub and contributors.
// Copyright (c) Meta Platforms, Inc. and affiliates.

use serde_json::Value;
use std::vec::Vec;

mod full_test;
#[rustfmt::skip]
#[allow(dead_code)]
mod full_test_vectors;
pub mod mock_rng;
mod parser;
mod rfc9807_vectors;
mod test_opaque_vectors;

pub(crate) fn decode(values: &Value, key: &str) -> Option<Vec<u8>> {
    values[key].as_str().and_then(|s| hex::decode(s).ok())
}
