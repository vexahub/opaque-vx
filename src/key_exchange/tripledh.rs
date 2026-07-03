// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) VexaHub and contributors.
// Copyright (c) Meta Platforms, Inc. and affiliates.

//! An implementation of the Triple Diffie-Hellman key exchange protocol

use core::marker::PhantomData;
use core::ops::Add;

use derive_where::derive_where;
use digest::block_api::{CoreProxy, SmallBlockSizeUser};
use digest::{Output, OutputSizeUser};
use generic_array::typenum::{IsLess, Le, NonZero, Sum, U256};
use generic_array::{ArrayLength, GenericArray};
use rand::{CryptoRng, Rng};
use subtle::{ConstantTimeEq, CtOption};

use super::{
    Deserialize, GenerateKe1Result, GenerateKe2Result, GenerateKe3Result, KeyExchange, Serialize,
    SerializedContext, SerializedCredentialRequest, SerializedCredentialResponse,
    SerializedIdentifiers,
};
use crate::ciphersuite::{CipherSuite, KeGroup};
use crate::errors::ProtocolError;
use crate::hash::{Hash, OutputSize, ProxyHash};
use crate::key_exchange::group::Group;
use crate::key_exchange::shared::{self, NonceLen};
pub use crate::key_exchange::shared::{DiffieHellman, Ke1Message, Ke1State};
use crate::keypair::{PrivateKey, PublicKey};
use crate::opaque::Identifiers;
use crate::serialization::{ConcatExt, SliceExt};

////////////////////////////
// High-level API Structs //
// ====================== //
////////////////////////////

/// The Triple Diffie-Hellman key exchange implementation
///
/// # Remote Key
///
/// [`ServerLoginBuilder::data()`](crate::ServerLoginBuilder::data()) will
/// return the client's ephemeral public key.
///
/// [`ServerLoginBuilder::build()`](crate::ServerLoginBuilder::build()) expects
/// a shared secret computed through Diffie-Hellman from the servers private key
/// and the given public key.
pub struct TripleDh<G, H>(PhantomData<(G, H)>);

/// The server state produced after the second key exchange message
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(bound = "")
)]
#[derive_where(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, ZeroizeOnDrop)]
pub struct Ke2State<H: OutputSizeUser> {
    pub(super) session_key: Output<H>,
    pub(super) expected_mac: Output<H>,
}

/// Builder for the second key exchange message
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(bound(
        deserialize = "H: serde::Deserialize<'de>,  PublicKey<G>: serde::Deserialize<'de>",
        serialize = "H: serde::Serialize, PublicKey<G>: serde::Serialize",
    ))
)]
#[derive_where(Clone, ZeroizeOnDrop)]
#[derive_where(Debug, Eq, Hash, PartialEq; H, PublicKey<G>)]
pub struct Ke2Builder<G: Group, H: Hash>
where
    H::Core: ProxyHash,
    <<H as CoreProxy>::Core as SmallBlockSizeUser>::_BlockSize: IsLess<U256>,
    Le<<<H as CoreProxy>::Core as SmallBlockSizeUser>::_BlockSize, U256>: NonZero,
    OutputSize<H>: ArrayLength,
{
    server_nonce: GenericArray<u8, NonceLen>,
    transcript_hasher: H,
    #[derive_where(skip(Zeroize))]
    client_e_pk: PublicKey<G>,
    #[derive_where(skip(Zeroize))]
    server_e_pk: PublicKey<G>,
    shared_secret_1: GenericArray<u8, G::PkLen>,
    shared_secret_3: GenericArray<u8, G::PkLen>,
}

/// The second key exchange message
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(bound(
        deserialize = "G::Pk: serde::Deserialize<'de>",
        serialize = "G::Pk: serde::Serialize"
    ))
)]
#[derive_where(Clone, ZeroizeOnDrop)]
#[derive_where(Debug, Eq, Hash, Ord, PartialEq, PartialOrd; G::Pk)]
pub struct Ke2Message<G: Group, H: Hash>
where
    H::Core: ProxyHash,
    <<H as CoreProxy>::Core as SmallBlockSizeUser>::_BlockSize: IsLess<U256>,
    Le<<<H as CoreProxy>::Core as SmallBlockSizeUser>::_BlockSize, U256>: NonZero,
    OutputSize<H>: ArrayLength,
{
    pub(super) server_nonce: GenericArray<u8, NonceLen>,
    #[derive_where(skip(Zeroize))]
    pub(super) server_e_pk: PublicKey<G>,
    pub(super) mac: Output<H>,
}

/// The third key exchange message
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(bound = "")
)]
#[derive_where(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, ZeroizeOnDrop)]
pub struct Ke3Message<H: Hash>
where
    H::Core: ProxyHash,
    <<H as CoreProxy>::Core as SmallBlockSizeUser>::_BlockSize: IsLess<U256>,
    Le<<<H as CoreProxy>::Core as SmallBlockSizeUser>::_BlockSize, U256>: NonZero,
    OutputSize<H>: ArrayLength,
{
    pub(super) mac: Output<H>,
}

////////////////////////////////
// High-level Implementations //
// ========================== //
////////////////////////////////

impl<G: Group + 'static, H: Hash> KeyExchange for TripleDh<G, H>
where
    G::Sk: DiffieHellman<G>,
    H::Core: ProxyHash,
    <<H as CoreProxy>::Core as SmallBlockSizeUser>::_BlockSize: IsLess<U256>,
    Le<<<H as CoreProxy>::Core as SmallBlockSizeUser>::_BlockSize, U256>: NonZero,
    OutputSize<H>: ArrayLength,
{
    type Group = G;
    type Hash = H;

    type KE1State = Ke1State<G>;
    type KE2State<CS: CipherSuite> = Ke2State<H>;
    type KE1Message = Ke1Message<G>;
    type KE2Builder<'a, CS: CipherSuite<KeyExchange = Self>> = Ke2Builder<G, H>;
    type KE2BuilderData<'a, CS: 'static + CipherSuite> = &'a PublicKey<G>;
    type KE2BuilderInput<CS: CipherSuite> = GenericArray<u8, G::PkLen>;
    type KE2Message = Ke2Message<G, H>;
    type KE3Message = Ke3Message<H>;

    fn generate_ke1<R: Rng + CryptoRng>(
        rng: &mut R,
    ) -> Result<GenerateKe1Result<Self>, ProtocolError> {
        shared::generate_ke1(rng)
    }

    fn ke2_builder<'a, CS: CipherSuite<KeyExchange = Self>, R: Rng + CryptoRng>(
        rng: &mut R,
        credential_request: SerializedCredentialRequest<CS>,
        ke1_message: Self::KE1Message,
        credential_response: SerializedCredentialResponse<CS>,
        client_s_pk: PublicKey<G>,
        identifiers: SerializedIdentifiers<'_, KeGroup<CS>>,
        context: SerializedContext<'a>,
    ) -> Result<Self::KE2Builder<'a, CS>, ProtocolError> {
        let shared::Ke2BuilderCommon {
            server_nonce,
            transcript_hasher,
            client_e_pk,
            server_e_pk,
            shared_secret_1,
            shared_secret_3,
        } = shared::ke2_builder_common::<G, H, CS, R>(
            rng,
            credential_request,
            ke1_message,
            credential_response,
            client_s_pk,
            identifiers,
            context,
        )?;

        Ok(Ke2Builder {
            server_nonce,
            transcript_hasher,
            client_e_pk,
            server_e_pk,
            shared_secret_1,
            shared_secret_3,
        })
    }

    fn ke2_builder_data<'a, CS: 'static + CipherSuite<KeyExchange = Self>>(
        builder: &'a Self::KE2Builder<'_, CS>,
    ) -> Self::KE2BuilderData<'a, CS> {
        &builder.client_e_pk
    }

    fn generate_ke2_input<CS: CipherSuite<KeyExchange = Self>, R: CryptoRng + Rng>(
        builder: &Self::KE2Builder<'_, CS>,
        _: &mut R,
        server_s_sk: &PrivateKey<G>,
    ) -> Self::KE2BuilderInput<CS> {
        server_s_sk.ke_diffie_hellman(&builder.client_e_pk)
    }

    fn build_ke2<CS: CipherSuite<KeyExchange = Self>>(
        mut builder: Self::KE2Builder<'_, CS>,
        shared_secret_2: Self::KE2BuilderInput<CS>,
    ) -> Result<GenerateKe2Result<CS>, ProtocolError> {
        let transcript_digest = builder.transcript_hasher.clone().finalize();
        let derived_keys = shared::derive_keys::<H>(
            [
                builder.shared_secret_1.as_slice(),
                &shared_secret_2,
                &builder.shared_secret_3,
            ]
            .into_iter(),
            &transcript_digest,
        )?;

        let (mac, expected_mac) = shared::compute_ke2_macs(
            &mut builder.transcript_hasher,
            &derived_keys,
            &transcript_digest,
        )?;

        Ok(GenerateKe2Result {
            state: Ke2State {
                session_key: derived_keys.session_key,
                expected_mac,
            },
            message: Ke2Message {
                server_nonce: builder.server_nonce,
                server_e_pk: builder.server_e_pk.clone(),
                mac,
            },
            #[cfg(test)]
            handshake_secret: derived_keys.handshake_secret,
            #[cfg(test)]
            km2: derived_keys.km2,
        })
    }

    fn generate_ke3<CS: CipherSuite<KeyExchange = Self>, R: CryptoRng + Rng>(
        _: &mut R,
        credential_request: SerializedCredentialRequest<CS>,
        ke1_message: Self::KE1Message,
        credential_response: SerializedCredentialResponse<CS>,
        ke1_state: &Self::KE1State,
        ke2_message: Self::KE2Message,
        server_s_pk: PublicKey<G>,
        client_s_sk: PrivateKey<G>,
        identifiers: SerializedIdentifiers<'_, KeGroup<CS>>,
        context: SerializedContext<'_>,
    ) -> Result<GenerateKe3Result<Self>, ProtocolError> {
        let mut transcript_hasher = shared::transcript(
            &context,
            &identifiers,
            &credential_request,
            &ke1_message.to_iter(),
            &credential_response,
            ke2_message.server_nonce,
            &ke2_message.server_e_pk.serialize(),
        );

        let shared_secret_1 = ke1_state
            .client_e_sk
            .ke_diffie_hellman(&ke2_message.server_e_pk);
        let shared_secret_2 = ke1_state.client_e_sk.ke_diffie_hellman(&server_s_pk);
        let shared_secret_3 = client_s_sk.ke_diffie_hellman(&ke2_message.server_e_pk);

        let (derived_keys, client_mac) = shared::finalize_ke3_transcript(
            &mut transcript_hasher,
            [
                shared_secret_1.as_slice(),
                shared_secret_2.as_slice(),
                shared_secret_3.as_slice(),
            ]
            .into_iter(),
            &ke2_message.mac,
        )?;

        Ok(GenerateKe3Result {
            session_key: derived_keys.session_key,
            message: Ke3Message { mac: client_mac },
            #[cfg(test)]
            handshake_secret: derived_keys.handshake_secret,
            #[cfg(test)]
            km3: derived_keys.km3,
        })
    }

    fn finish_ke<CS: CipherSuite>(
        ke2_state: &Self::KE2State<CS>,
        ke3_message: Self::KE3Message,
        _: Identifiers<'_>,
        _: SerializedContext<'_>,
    ) -> Result<Output<H>, ProtocolError> {
        CtOption::new(
            ke2_state.session_key.clone(),
            ke2_state.expected_mac.ct_eq(&ke3_message.mac),
        )
        .into_option()
        .ok_or(ProtocolError::InvalidLoginError)
    }
}

////////////////////////////////////////////////
// Trait Implementations //
// ========================================== //
////////////////////////////////////////////////

impl<H: Hash> Deserialize for Ke2State<H>
where
    H::Core: ProxyHash,
    <<H as CoreProxy>::Core as SmallBlockSizeUser>::_BlockSize: IsLess<U256>,
    Le<<<H as CoreProxy>::Core as SmallBlockSizeUser>::_BlockSize, U256>: NonZero,
    OutputSize<H>: ArrayLength,
{
    fn deserialize_take(input: &mut &[u8]) -> Result<Self, ProtocolError> {
        Ok(Self {
            session_key: input.take_array("session key")?.into_ha0_4(),
            expected_mac: input.take_array("expected mac")?.into_ha0_4(),
        })
    }
}

impl<H: Hash> Serialize for Ke2State<H>
where
    H::Core: ProxyHash,
    <<H as CoreProxy>::Core as SmallBlockSizeUser>::_BlockSize: IsLess<U256>,
    Le<<<H as CoreProxy>::Core as SmallBlockSizeUser>::_BlockSize, U256>: NonZero,
    OutputSize<H>: ArrayLength,
    // Ke2State: Hash + Hash
    OutputSize<H>: Add<OutputSize<H>>,
    Sum<OutputSize<H>, OutputSize<H>>: ArrayLength,
{
    type Len = Sum<OutputSize<H>, OutputSize<H>>;

    fn serialize(&self) -> GenericArray<u8, Self::Len> {
        let sk: GenericArray<u8, OutputSize<H>> =
            GenericArray::from_slice(self.session_key.as_slice()).clone();
        let mac: GenericArray<u8, OutputSize<H>> =
            GenericArray::from_slice(self.expected_mac.as_slice()).clone();

        sk.cat(mac)
    }
}

impl<G: Group, H: Hash> Deserialize for Ke2Message<G, H>
where
    H::Core: ProxyHash,
    <<H as CoreProxy>::Core as SmallBlockSizeUser>::_BlockSize: IsLess<U256>,
    Le<<<H as CoreProxy>::Core as SmallBlockSizeUser>::_BlockSize, U256>: NonZero,
    OutputSize<H>: ArrayLength,
{
    fn deserialize_take(input: &mut &[u8]) -> Result<Self, ProtocolError> {
        Ok(Self {
            server_nonce: input.take_array("server nonce")?,
            server_e_pk: PublicKey::deserialize_take(input)?,
            mac: input.take_array("mac")?.into_ha0_4(),
        })
    }
}

impl<H: Hash, G: Group> Serialize for Ke2Message<G, H>
where
    H::Core: ProxyHash,
    <<H as CoreProxy>::Core as SmallBlockSizeUser>::_BlockSize: IsLess<U256>,
    Le<<<H as CoreProxy>::Core as SmallBlockSizeUser>::_BlockSize, U256>: NonZero,
    OutputSize<H>: ArrayLength,
    // Ke2Message: (Nonce + KePk) + Hash
    NonceLen: Add<G::PkLen>,
    Sum<NonceLen, G::PkLen>: ArrayLength + Add<OutputSize<H>>,
    Sum<Sum<NonceLen, G::PkLen>, OutputSize<H>>: ArrayLength,
{
    type Len = Sum<Sum<NonceLen, G::PkLen>, OutputSize<H>>;

    fn serialize(&self) -> GenericArray<u8, Self::Len> {
        self.server_nonce
            .cat(self.server_e_pk.serialize())
            .cat(GenericArray::from_slice(self.mac.as_slice()).clone())
    }
}

impl<H: Hash> Deserialize for Ke3Message<H>
where
    H::Core: ProxyHash,
    <<H as CoreProxy>::Core as SmallBlockSizeUser>::_BlockSize: IsLess<U256>,
    Le<<<H as CoreProxy>::Core as SmallBlockSizeUser>::_BlockSize, U256>: NonZero,
    OutputSize<H>: ArrayLength,
{
    fn deserialize_take(bytes: &mut &[u8]) -> Result<Self, ProtocolError> {
        Ok(Self {
            mac: bytes.take_array("mac")?.into_ha0_4(),
        })
    }
}

impl<H: Hash> Serialize for Ke3Message<H>
where
    H::Core: ProxyHash,
    <<H as CoreProxy>::Core as SmallBlockSizeUser>::_BlockSize: IsLess<U256>,
    Le<<<H as CoreProxy>::Core as SmallBlockSizeUser>::_BlockSize, U256>: NonZero,
    OutputSize<H>: ArrayLength,
{
    type Len = OutputSize<H>;

    fn serialize(&self) -> GenericArray<u8, Self::Len> {
        GenericArray::from_slice(self.mac.as_slice()).clone()
    }
}
