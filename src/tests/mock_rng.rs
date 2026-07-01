// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) VexaHub and contributors.
// Copyright (c) Meta Platforms, Inc. and affiliates.

use core::cmp::min;
use std::vec::Vec;

use core::convert::Infallible;
use rand_core::{TryCryptoRng, TryRng};

/// A simple implementation of `Rng` for testing purposes.
///
/// This generates a cyclic sequence (i.e. cycles over an initial buffer)
#[derive(Clone, Debug)]
pub struct CycleRng {
    v: Vec<u8>,
}

impl CycleRng {
    /// Create a `CycleRng`, yielding a sequence starting with `initial` and
    /// looping thereafter
    pub fn new(initial: Vec<u8>) -> Self {
        CycleRng { v: initial }
    }
}

fn rotate_left<T>(data: &mut [T], steps: usize) {
    if data.is_empty() {
        return;
    }
    let steps = steps % data.len();

    data[..steps].reverse();
    data[steps..].reverse();
    data.reverse();
}

impl TryRng for CycleRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut buf = [0u8; 4];

        self.try_fill_bytes(&mut buf)?;

        Ok(u32::from_le_bytes(buf))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut buf = [0u8; 8];

        self.try_fill_bytes(&mut buf)?;

        Ok(u64::from_le_bytes(buf))
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
        let len = min(self.v.len(), dest.len());

        dest[..len].copy_from_slice(&self.v[..len]);

        rotate_left(&mut self.v, len);

        Ok(())
    }
}

// This is meant for testing only
impl TryCryptoRng for CycleRng {}
