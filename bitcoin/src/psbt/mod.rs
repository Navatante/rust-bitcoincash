// SPDX-License-Identifier: CC0-1.0

//! Partially Signed Bitcoin Transactions.
//!
//! Implementation of BIP-0174 Partially Signed Bitcoin Transaction Format as
//! defined at <https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki>
//! except we define PSBTs containing non-standard sighash types as invalid.

#[macro_use]
mod macros;
mod error;
mod map;
pub mod raw;
pub mod serialize;

use core::convert::Infallible;
use core::{cmp, fmt};
#[cfg(feature = "std")]
use std::collections::{HashMap, HashSet};

use internals::write_err;
use secp256k1::{Message, Secp256k1, Signing, Verification};

use crate::bip32::{self, KeySource, Xpriv, Xpub};
use crate::crypto::key::{PrivateKey, PublicKey};
use crate::crypto::ecdsa;
use crate::prelude::{btree_map, BTreeMap, BTreeSet, Borrow, Box, Vec};
use crate::script::{ScriptExt as _, ScriptPubKeyExt as _};
use crate::sighash::{self, EcdsaSighashType, SighashCache};
use crate::transaction::{self, Transaction, TransactionExt as _, TxOut};
use crate::{Amount, FeeRate};

#[rustfmt::skip]                // Keep public re-exports separate.
#[doc(inline)]
pub use self::{
    map::{Input, Output, PsbtSighashType},
    error::Error,
};

/// A Partially Signed Transaction.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Psbt {
    /// The unsigned transaction, scriptSigs and witnesses for each input must be empty.
    pub unsigned_tx: Transaction,
    /// The version number of this PSBT. If omitted, the version number is 0.
    pub version: u32,
    /// A global map from extended public keys to the used key fingerprint and
    /// derivation path as defined by BIP 32.
    pub xpub: BTreeMap<Xpub, KeySource>,
    /// Global proprietary key-value pairs.
    pub proprietary: BTreeMap<raw::ProprietaryKey, Vec<u8>>,
    /// Unknown global key-value pairs.
    pub unknown: BTreeMap<raw::Key, Vec<u8>>,

    /// The corresponding key-value map for each input in the unsigned transaction.
    pub inputs: Vec<Input>,
    /// The corresponding key-value map for each output in the unsigned transaction.
    pub outputs: Vec<Output>,
}

impl Psbt {
    /// Returns an iterator for the funding UTXOs of the psbt
    ///
    /// For each PSBT input that contains UTXO information `Ok` is returned containing that information.
    /// The order of returned items is same as the order of inputs.
    ///
    /// # Errors
    ///
    /// The function returns error when UTXO information is not present or is invalid.
    ///
    /// # Panics
    ///
    /// The function panics if the length of transaction inputs is not equal to the length of PSBT inputs.
    pub fn iter_funding_utxos(&self) -> impl Iterator<Item = Result<&TxOut, Error>> {
        assert_eq!(self.inputs.len(), self.unsigned_tx.inputs.len());
        self.unsigned_tx.inputs.iter().zip(&self.inputs).map(|(tx_input, psbt_input)| {
            match (&psbt_input.witness_utxo, &psbt_input.non_witness_utxo) {
                (Some(witness_utxo), _) => Ok(witness_utxo),
                (None, Some(non_witness_utxo)) => {
                    let vout = tx_input.previous_output.vout as usize;
                    non_witness_utxo.outputs.get(vout).ok_or(Error::PsbtUtxoOutOfbounds)
                }
                (None, None) => Err(Error::MissingUtxo),
            }
        })
    }

    /// Checks that unsigned transaction does not have scriptSig's or witness data.
    fn unsigned_tx_checks(&self) -> Result<(), Error> {
        for txin in &self.unsigned_tx.inputs {
            if !txin.script_sig.is_empty() {
                return Err(Error::UnsignedTxHasScriptSigs);
            }

            // BCH: no witness field
        }

        Ok(())
    }

    /// Constructs a new PSBT from an unsigned transaction.
    ///
    /// # Errors
    ///
    /// If transactions is not unsigned.
    pub fn from_unsigned_tx(tx: Transaction) -> Result<Self, Error> {
        let psbt = Psbt {
            inputs: vec![Default::default(); tx.inputs.len()],
            outputs: vec![Default::default(); tx.outputs.len()],

            unsigned_tx: tx,
            xpub: Default::default(),
            version: 0,
            proprietary: Default::default(),
            unknown: Default::default(),
        };
        psbt.unsigned_tx_checks()?;
        Ok(psbt)
    }

    /// The default `max_fee_rate` value used for extracting transactions with [`extract_tx`]
    ///
    /// As of 2023, even the biggest overpayers during the highest fee markets only paid around
    /// 1000 sats/vByte. 25k sats/vByte is obviously a mistake at this point.
    ///
    /// [`extract_tx`]: Psbt::extract_tx
    pub const DEFAULT_MAX_FEE_RATE: FeeRate = FeeRate::from_sat_per_vb(25_000);

    /// An alias for [`extract_tx_fee_rate_limit`].
    ///
    /// [`extract_tx_fee_rate_limit`]: Psbt::extract_tx_fee_rate_limit
    #[allow(clippy::result_large_err)] // The PSBT returned in `SendingToomuch` is large.
    pub fn extract_tx(self) -> Result<Transaction, ExtractTxError> {
        self.internal_extract_tx_with_fee_rate_limit(Self::DEFAULT_MAX_FEE_RATE)
    }

    /// Extracts the [`Transaction`] from a [`Psbt`] by filling in the available signature information.
    ///
    /// # Errors
    ///
    /// [`ExtractTxError`] variants will contain either the [`Psbt`] itself or the [`Transaction`]
    /// that was extracted. These can be extracted from the Errors in order to recover.
    /// See the error documentation for info on the variants. In general, it covers large fees.
    #[allow(clippy::result_large_err)] // The PSBT returned in `SendingToomuch` is large.
    pub fn extract_tx_fee_rate_limit(self) -> Result<Transaction, ExtractTxError> {
        self.internal_extract_tx_with_fee_rate_limit(Self::DEFAULT_MAX_FEE_RATE)
    }

    /// Extracts the [`Transaction`] from a [`Psbt`] by filling in the available signature information.
    ///
    /// # Errors
    ///
    /// See [`extract_tx`].
    ///
    /// [`extract_tx`]: Psbt::extract_tx
    #[allow(clippy::result_large_err)] // The PSBT returned in `SendingToomuch` is large.
    pub fn extract_tx_with_fee_rate_limit(
        self,
        max_fee_rate: FeeRate,
    ) -> Result<Transaction, ExtractTxError> {
        self.internal_extract_tx_with_fee_rate_limit(max_fee_rate)
    }

    /// Perform [`extract_tx_fee_rate_limit`] without the fee rate check.
    ///
    /// This can result in a transaction with absurdly high fees. Use with caution.
    ///
    /// [`extract_tx_fee_rate_limit`]: Psbt::extract_tx_fee_rate_limit
    pub fn extract_tx_unchecked_fee_rate(self) -> Transaction { self.internal_extract_tx() }

    #[inline]
    fn internal_extract_tx(self) -> Transaction {
        let mut tx: Transaction = self.unsigned_tx;

        for (vin, psbtin) in tx.inputs.iter_mut().zip(self.inputs.into_iter()) {
            vin.script_sig = psbtin.final_script_sig.unwrap_or_default();
        }

        tx
    }

    #[inline]
    #[allow(clippy::result_large_err)] // The PSBT returned in `SendingToomuch` is large.
    fn internal_extract_tx_with_fee_rate_limit(
        self,
        max_fee_rate: FeeRate,
    ) -> Result<Transaction, ExtractTxError> {
        let fee = match self.fee() {
            Ok(fee) => fee,
            Err(Error::MissingUtxo) =>
                return Err(ExtractTxError::MissingInputValue { tx: self.internal_extract_tx() }),
            Err(Error::NegativeFee) => return Err(ExtractTxError::SendingTooMuch { psbt: self }),
            Err(Error::FeeOverflow) =>
                return Err(ExtractTxError::AbsurdFeeRate {
                    fee_rate: FeeRate::MAX,
                    tx: self.internal_extract_tx(),
                }),
            _ => unreachable!(),
        };

        // Note: Move prevents usage of &self from now on.
        let tx = self.internal_extract_tx();

        let fee_rate = (fee / tx.weight()).unwrap_or(FeeRate::MAX);
        if fee_rate > max_fee_rate {
            Err(ExtractTxError::AbsurdFeeRate { fee_rate, tx })
        } else {
            Ok(tx)
        }
    }

    /// Combines this [`Psbt`] with `other` PSBT as described by BIP-0174.
    ///
    /// In accordance with BIP-0174 this function is commutative i.e., `A.combine(B) == B.combine(A)`
    pub fn combine(&mut self, other: Self) -> Result<(), Error> {
        if self.unsigned_tx != other.unsigned_tx {
            return Err(Error::UnexpectedUnsignedTx {
                expected: Box::new(self.unsigned_tx.clone()),
                actual: Box::new(other.unsigned_tx),
            });
        }

        // BIP-0174: The Combiner must remove any duplicate key-value pairs, in accordance with
        //          the specification. It can pick arbitrarily when conflicts occur.

        // Keeping the highest version
        self.version = cmp::max(self.version, other.version);

        // Merging xpubs
        for (xpub, (fingerprint1, derivation1)) in other.xpub {
            match self.xpub.entry(xpub) {
                btree_map::Entry::Vacant(entry) => {
                    entry.insert((fingerprint1, derivation1));
                }
                btree_map::Entry::Occupied(mut entry) => {
                    // Here in case of the conflict we select the version with algorithm:
                    // 1) if everything is equal we do nothing
                    // 2) report an error if
                    //    - derivation paths are equal and fingerprints are not
                    //    - derivation paths are of the same length, but not equal
                    //    - derivation paths has different length, but the shorter one
                    //      is not the strict suffix of the longer one
                    // 3) choose longest derivation otherwise

                    let (fingerprint2, derivation2) = entry.get().clone();

                    if (derivation1 == derivation2 && fingerprint1 == fingerprint2)
                        || (derivation1.len() < derivation2.len()
                            && derivation1[..]
                                == derivation2[derivation2.len() - derivation1.len()..])
                    {
                        continue;
                    } else if derivation2.len() <= derivation1.len()
                        && derivation2[..] == derivation1[derivation1.len() - derivation2.len()..]
                    {
                        entry.insert((fingerprint1, derivation1));
                        continue;
                    }
                    return Err(Error::CombineInconsistentKeySources(Box::new(xpub)));
                }
            }
        }

        self.proprietary.extend(other.proprietary);
        self.unknown.extend(other.unknown);

        for (self_input, other_input) in self.inputs.iter_mut().zip(other.inputs.into_iter()) {
            self_input.combine(other_input);
        }

        for (self_output, other_output) in self.outputs.iter_mut().zip(other.outputs.into_iter()) {
            self_output.combine(other_output);
        }

        Ok(())
    }

    /// Attempts to create _all_ the required signatures for this PSBT using `k`.
    ///
    /// If you just want to sign an input with one specific key consider using `sighash_ecdsa`.
    /// This function does not support scripts that contain `OP_CODESEPARATOR`.
    ///
    /// # Returns
    ///
    /// A map of input index -> keys used to sign.
    ///
    /// If an error is returned some signatures may already have been added to the PSBT. Since
    /// `partial_sigs` is a [`BTreeMap`] it is safe to retry, previous sigs will be overwritten.
    pub fn sign<C, K>(
        &mut self,
        k: &K,
        secp: &Secp256k1<C>,
    ) -> Result<SigningKeysMap, (SigningKeysMap, SigningErrors)>
    where
        C: Signing + Verification,
        K: GetKey,
    {
        let tx = self.unsigned_tx.clone(); // clone because we need to mutably borrow when signing.
        let mut cache = SighashCache::new(&tx);

        let mut used = BTreeMap::new();
        let mut errors = BTreeMap::new();

        for i in 0..self.inputs.len() {
            match self.signing_algorithm(i) {
                Ok(SigningAlgorithm::Ecdsa) =>
                    match self.bip32_sign_ecdsa(k, i, &mut cache, secp) {
                        Ok(v) => {
                            used.insert(i, SigningKeys::Ecdsa(v));
                        }
                        Err(e) => {
                            errors.insert(i, e);
                        }
                    },
                Err(e) => {
                    errors.insert(i, e);
                }
            }
        }
        if errors.is_empty() {
            Ok(used)
        } else {
            Err((used, errors))
        }
    }

    /// Attempts to create all signatures required by this PSBT's `bip32_derivation` field, adding
    /// them to `partial_sigs`.
    ///
    /// # Returns
    ///
    /// - Ok: A list of the public keys used in signing.
    /// - Err: Error encountered trying to calculate the sighash AND we had the signing key.
    fn bip32_sign_ecdsa<C, K, T>(
        &mut self,
        k: &K,
        input_index: usize,
        cache: &mut SighashCache<T>,
        secp: &Secp256k1<C>,
    ) -> Result<Vec<PublicKey>, SignError>
    where
        C: Signing,
        T: Borrow<Transaction>,
        K: GetKey,
    {
        let msg_sighash_ty_res = self.sighash_ecdsa(input_index, cache);

        let input = &mut self.inputs[input_index]; // Index checked in call to `sighash_ecdsa`.

        let mut used = vec![]; // List of pubkeys used to sign the input.

        for (pk, key_source) in input.bip32_derivation.iter() {
            let sk = if let Ok(Some(sk)) = k.get_key(&KeyRequest::Bip32(key_source.clone()), secp) {
                sk
            } else if let Ok(Some(sk)) = k.get_key(&KeyRequest::Pubkey(PublicKey::new(*pk)), secp) {
                sk
            } else {
                continue;
            };

            // Only return the error if we have a secret key to sign this input.
            let (msg, sighash_ty) = match msg_sighash_ty_res {
                Err(e) => return Err(e),
                Ok((msg, sighash_ty)) => (msg, sighash_ty),
            };

            let sig = ecdsa::Signature {
                signature: secp.sign_ecdsa(&msg, &sk.inner),
                sighash_type: sighash_ty,
            };

            let pk = sk.public_key(secp);

            input.partial_sigs.insert(pk, sig);
            used.push(pk);
        }

        Ok(used)
    }

    /// Returns the sighash message to sign an ECDSA input along with the sighash type.
    ///
    /// Uses the [`EcdsaSighashType`] from this input if one is specified. If no sighash type is
    /// specified uses [`EcdsaSighashType::All`]. This function does not support scripts that
    /// contain `OP_CODESEPARATOR`.
    pub fn sighash_ecdsa<T: Borrow<Transaction>>(
        &self,
        input_index: usize,
        cache: &mut SighashCache<T>,
    ) -> Result<(Message, EcdsaSighashType), SignError> {
        use OutputType::*;

        if self.signing_algorithm(input_index)? != SigningAlgorithm::Ecdsa {
            return Err(SignError::WrongSigningAlgorithm);
        }

        let input = self.checked_input(input_index)?;
        let utxo = self.spend_utxo(input_index)?;
        let spk = &utxo.script_pubkey; // scriptPubkey for input spend utxo.

        let hash_ty = input.ecdsa_hash_ty().map_err(|_| SignError::InvalidSighashType)?; // Only support standard sighash types.

        match self.output_type(input_index)? {
            Bare => {
                let sighash = cache
                    .legacy_signature_hash(input_index, spk, hash_ty.to_u32())
                    .expect("input checked above");
                Ok((Message::from(sighash), hash_ty))
            }
            Sh => {
                let script_code =
                    input.redeem_script.as_ref().ok_or(SignError::MissingRedeemScript)?;
                let sighash = cache
                    .legacy_signature_hash(input_index, script_code, hash_ty.to_u32())
                    .expect("input checked above");
                Ok((Message::from(sighash), hash_ty))
            }
        }
    }

    /// Returns the spending utxo for this PSBT's input at `input_index`.
    pub fn spend_utxo(&self, input_index: usize) -> Result<&TxOut, SignError> {
        let input = self.checked_input(input_index)?;
        let utxo = if let Some(witness_utxo) = &input.witness_utxo {
            witness_utxo
        } else if let Some(non_witness_utxo) = &input.non_witness_utxo {
            let vout = self.unsigned_tx.inputs[input_index].previous_output.vout;
            &non_witness_utxo.outputs[vout as usize]
        } else {
            return Err(SignError::MissingSpendUtxo);
        };
        Ok(utxo)
    }

    /// Gets the input at `input_index` after checking that it is a valid index.
    fn checked_input(&self, input_index: usize) -> Result<&Input, IndexOutOfBoundsError> {
        // No `?` operator in const context.
        match self.check_index_is_within_bounds(input_index) {
            Ok(_) => Ok(&self.inputs[input_index]),
            Err(e) => Err(e),
        }
    }

    /// Checks `input_index` is within bounds for the PSBT `inputs` array and
    /// for the PSBT `unsigned_tx` `input` array.
    fn check_index_is_within_bounds(
        &self,
        input_index: usize,
    ) -> Result<(), IndexOutOfBoundsError> {
        if input_index >= self.inputs.len() {
            return Err(IndexOutOfBoundsError::Inputs {
                index: input_index,
                length: self.inputs.len(),
            });
        }

        if input_index >= self.unsigned_tx.inputs.len() {
            return Err(IndexOutOfBoundsError::TxInput {
                index: input_index,
                length: self.unsigned_tx.inputs.len(),
            });
        }

        Ok(())
    }

    /// Returns the algorithm used to sign this PSBT's input at `input_index`.
    fn signing_algorithm(&self, input_index: usize) -> Result<SigningAlgorithm, SignError> {
        let output_type = self.output_type(input_index)?;
        Ok(output_type.signing_algorithm())
    }

    /// Returns the [`OutputType`] of the spend utxo for this PBST's input at `input_index`.
    fn output_type(&self, input_index: usize) -> Result<OutputType, SignError> {
        let _input = self.checked_input(input_index)?;
        let utxo = self.spend_utxo(input_index)?;
        let spk = utxo.script_pubkey.clone();

        if spk.is_p2sh() {
            return Ok(OutputType::Sh);
        }

        // Bare (P2PK, P2PKH, etc.)
        Ok(OutputType::Bare)
    }

    /// Calculates transaction fee.
    ///
    /// 'Fee' being the amount that will be paid for mining a transaction with the current inputs
    /// and outputs i.e., the difference in value of the total inputs and the total outputs.
    ///
    /// # Errors
    ///
    /// - [`Error::MissingUtxo`] when UTXO information for any input is not present or is invalid.
    /// - [`Error::NegativeFee`] if calculated value is negative.
    /// - [`Error::FeeOverflow`] if an integer overflow occurs.
    pub fn fee(&self) -> Result<Amount, Error> {
        let mut inputs = Amount::ZERO;
        for utxo in self.iter_funding_utxos() {
            inputs = inputs.checked_add(utxo?.value).ok_or(Error::FeeOverflow)?;
        }
        let mut outputs = Amount::ZERO;
        for out in &self.unsigned_tx.outputs {
            outputs = outputs.checked_add(out.value).ok_or(Error::FeeOverflow)?;
        }
        inputs.checked_sub(outputs).ok_or(Error::NegativeFee)
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for Psbt {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use crate::prelude::ToString;

        if serializer.is_human_readable() {
            serializer.serialize_str(&self.to_string())
        } else {
            serializer.serialize_bytes(&self.serialize())
        }
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Psbt {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct Visitor;

        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = Psbt;

            fn expecting(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
                write!(f, "a psbt")
            }

            fn visit_bytes<E: serde::de::Error>(self, bytes: &[u8]) -> Result<Self::Value, E> {
                Psbt::deserialize(bytes).map_err(|e| serde::de::Error::custom(e))
            }

            fn visit_str<E: serde::de::Error>(self, s: &str) -> Result<Self::Value, E> {
                s.parse().map_err(|e| serde::de::Error::custom(e))
            }
        }

        if deserializer.is_human_readable() {
            deserializer.deserialize_str(Visitor)
        } else {
            deserializer.deserialize_bytes(Visitor)
        }
    }
}

/// Data required to call [`GetKey`] to get the private key to sign an input.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum KeyRequest {
    /// Request a private key using the associated public key.
    Pubkey(PublicKey),
    /// Request a private key using BIP-0032 fingerprint and derivation path.
    Bip32(KeySource),
}

/// Trait to get a private key from a key request, key is then used to sign an input.
pub trait GetKey {
    /// An error occurred while getting the key.
    type Error: core::fmt::Debug;

    /// Attempts to get the private key for `key_request`.
    ///
    /// # Returns
    ///
    /// - `Some(key)` if the key is found.
    /// - `None` if the key was not found but no error was encountered.
    /// - `Err` if an error was encountered while looking for the key.
    fn get_key<C: Signing>(
        &self,
        key_request: &KeyRequest,
        secp: &Secp256k1<C>,
    ) -> Result<Option<PrivateKey>, Self::Error>;
}

impl GetKey for Xpriv {
    type Error = GetKeyError;

    fn get_key<C: Signing>(
        &self,
        key_request: &KeyRequest,
        secp: &Secp256k1<C>,
    ) -> Result<Option<PrivateKey>, Self::Error> {
        match key_request {
            KeyRequest::Pubkey(_) => Err(GetKeyError::NotSupported),
            KeyRequest::Bip32((fingerprint, path)) => {
                let key = if self.fingerprint(secp) == *fingerprint {
                    let k = self.derive_xpriv(secp, path).map_err(GetKeyError::Bip32)?;
                    Some(k.to_private_key())
                } else if self.parent_fingerprint == *fingerprint
                    && !path.is_empty()
                    && path[0] == self.child_number
                {
                    let k = self.derive_xpriv(secp, &path[1..]).map_err(GetKeyError::Bip32)?;
                    Some(k.to_private_key())
                } else {
                    None
                };
                Ok(key)
            }
        }
    }
}

/// Map of input index -> signing key for that input (see [`SigningKeys`]).
pub type SigningKeysMap = BTreeMap<usize, SigningKeys>;

/// A list of keys used to sign an input.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum SigningKeys {
    /// Keys used to sign an ECDSA input.
    Ecdsa(Vec<PublicKey>),
}

/// Map of input index -> the error encountered while attempting to sign that input.
pub type SigningErrors = BTreeMap<usize, SignError>;

#[rustfmt::skip]
macro_rules! impl_get_key_for_set {
    ($set:ident) => {

impl GetKey for $set<Xpriv> {
    type Error = GetKeyError;

    fn get_key<C: Signing>(
        &self,
        key_request: &KeyRequest,
        secp: &Secp256k1<C>
    ) -> Result<Option<PrivateKey>, Self::Error> {
        // OK to stop at the first error because Xpriv::get_key() can only fail
        // if this isn't a KeyRequest::Bip32, which would fail for all Xprivs.
        self.iter()
            .find_map(|xpriv| xpriv.get_key(key_request, secp).transpose())
            .transpose()
    }
}}}
impl_get_key_for_set!(Vec);
impl_get_key_for_set!(BTreeSet);
#[cfg(feature = "std")]
impl_get_key_for_set!(HashSet);

#[rustfmt::skip]
macro_rules! impl_get_key_for_pubkey_map {
    ($map:ident) => {

impl GetKey for $map<PublicKey, PrivateKey> {
    type Error = GetKeyError;

    fn get_key<C: Signing>(
        &self,
        key_request: &KeyRequest,
        _: &Secp256k1<C>,
    ) -> Result<Option<PrivateKey>, Self::Error> {
        match key_request {
            KeyRequest::Pubkey(pk) => Ok(self.get(&pk).cloned()),
            KeyRequest::Bip32(_) => Err(GetKeyError::NotSupported),
        }
    }
}}}
impl_get_key_for_pubkey_map!(BTreeMap);
#[cfg(feature = "std")]
impl_get_key_for_pubkey_map!(HashMap);

/// Errors when getting a key.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum GetKeyError {
    /// A bip32 derivation error.
    Bip32(bip32::DerivationError),
    /// The GetKey operation is not supported for this key request.
    NotSupported,
}

impl From<Infallible> for GetKeyError {
    fn from(never: Infallible) -> Self { match never {} }
}

impl fmt::Display for GetKeyError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use GetKeyError::*;

        match *self {
            Bip32(ref e) => write_err!(f, "bip32 derivation"; e),
            NotSupported =>
                f.write_str("the GetKey operation is not supported for this key request"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for GetKeyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use GetKeyError::*;

        match *self {
            NotSupported => None,
            Bip32(ref e) => Some(e),
        }
    }
}

/// The various output types supported by the Bitcoin network.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum OutputType {
    /// An output of type: pay-to-pubkey or pay-to-pubkey-hash.
    Bare,
    /// A pay-to-script-hash output (P2SH).
    Sh,
}

impl OutputType {
    /// The signing algorithm used to sign this output type.
    pub fn signing_algorithm(&self) -> SigningAlgorithm {
        use OutputType::*;

        match self {
            Bare | Sh => SigningAlgorithm::Ecdsa,
        }
    }
}

/// Signing algorithms supported by the Bitcoin network.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SigningAlgorithm {
    /// The Elliptic Curve Digital Signature Algorithm (see [wikipedia]).
    ///
    /// [wikipedia]: https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm
    Ecdsa,
}

/// Errors encountered while calculating the sighash message.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SignError {
    /// Input index out of bounds.
    IndexOutOfBounds(IndexOutOfBoundsError),
    /// Invalid Sighash type.
    InvalidSighashType,
    /// Missing input utxo.
    MissingInputUtxo,
    /// Missing Redeem script.
    MissingRedeemScript,
    /// Missing spending utxo.
    MissingSpendUtxo,
    /// Missing witness script.
    MissingWitnessScript,
    /// Signing algorithm and key type does not match.
    MismatchedAlgoKey,
    /// Attempted to ECDSA sign an non-ECDSA input.
    NotEcdsa,
    /// Unable to determine the output type.
    UnknownOutputType,
    /// Unable to find key.
    KeyNotFound,
    /// Attempt to sign an input with the wrong signing algorithm.
    WrongSigningAlgorithm,
    /// Signing request currently unsupported.
    Unsupported,
}

impl From<Infallible> for SignError {
    fn from(never: Infallible) -> Self { match never {} }
}

impl fmt::Display for SignError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use SignError::*;

        match *self {
            IndexOutOfBounds(ref e) => write_err!(f, "index out of bounds"; e),
            InvalidSighashType => write!(f, "invalid sighash type"),
            MissingInputUtxo => write!(f, "missing input utxo in PBST"),
            MissingRedeemScript => write!(f, "missing redeem script"),
            MissingSpendUtxo => write!(f, "missing spend utxo in PSBT"),
            MissingWitnessScript => write!(f, "missing witness script"),
            MismatchedAlgoKey => write!(f, "signing algorithm and key type does not match"),
            NotEcdsa => write!(f, "attempted to ECDSA sign an non-ECDSA input"),
            UnknownOutputType => write!(f, "unable to determine the output type"),
            KeyNotFound => write!(f, "unable to find key"),
            WrongSigningAlgorithm =>
                write!(f, "attempt to sign an input with the wrong signing algorithm"),
            Unsupported => write!(f, "signing request currently unsupported"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for SignError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use SignError::*;

        match *self {
            IndexOutOfBounds(ref e) => Some(e),
            InvalidSighashType
            | MissingInputUtxo
            | MissingRedeemScript
            | MissingSpendUtxo
            | MissingWitnessScript
            | MismatchedAlgoKey
            | NotEcdsa
            | UnknownOutputType
            | KeyNotFound
            | WrongSigningAlgorithm
            | Unsupported => None,
        }
    }
}

impl From<IndexOutOfBoundsError> for SignError {
    fn from(e: IndexOutOfBoundsError) -> Self { SignError::IndexOutOfBounds(e) }
}

/// This error is returned when extracting a [`Transaction`] from a [`Psbt`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ExtractTxError {
    /// The [`FeeRate`] is too high
    AbsurdFeeRate {
        /// The [`FeeRate`]
        fee_rate: FeeRate,
        /// The extracted [`Transaction`] (use this to ignore the error)
        tx: Transaction,
    },
    /// One or more of the inputs lacks value information (witness_utxo or non_witness_utxo)
    MissingInputValue {
        /// The extracted [`Transaction`] (use this to ignore the error)
        tx: Transaction,
    },
    /// Input value is less than Output Value, and the [`Transaction`] would be invalid.
    SendingTooMuch {
        /// The original [`Psbt`] is returned untouched.
        psbt: Psbt,
    },
}

impl From<Infallible> for ExtractTxError {
    fn from(never: Infallible) -> Self { match never {} }
}

impl fmt::Display for ExtractTxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use ExtractTxError::*;

        match *self {
            AbsurdFeeRate { fee_rate, .. } => write!(
                f,
                "an absurdly high fee rate of {} sat/kwu",
                fee_rate.to_sat_per_kwu_floor()
            ),
            MissingInputValue { .. } => write!(
                f,
                "one of the inputs lacked value information (witness_utxo or non_witness_utxo)"
            ),
            SendingTooMuch { .. } => write!(
                f,
                "transaction would be invalid due to output value being greater than input value."
            ),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ExtractTxError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use ExtractTxError::*;

        match *self {
            AbsurdFeeRate { .. } | MissingInputValue { .. } | SendingTooMuch { .. } => None,
        }
    }
}

/// Input index out of bounds (actual index, maximum index allowed).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum IndexOutOfBoundsError {
    /// The index is out of bounds for the `psbt.inputs` vector.
    Inputs {
        /// Attempted index access.
        index: usize,
        /// Length of the PBST inputs vector.
        length: usize,
    },
    /// The index is out of bounds for the `psbt.unsigned_tx.input` vector.
    TxInput {
        /// Attempted index access.
        index: usize,
        /// Length of the PBST's unsigned transaction input vector.
        length: usize,
    },
}

impl From<Infallible> for IndexOutOfBoundsError {
    fn from(never: Infallible) -> Self { match never {} }
}

impl fmt::Display for IndexOutOfBoundsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use IndexOutOfBoundsError::*;

        match *self {
            Inputs { ref index, ref length } => write!(
                f,
                "index {} is out-of-bounds for PSBT inputs vector length {}",
                index, length
            ),
            TxInput { ref index, ref length } => write!(
                f,
                "index {} is out-of-bounds for PSBT unsigned tx input vector length {}",
                index, length
            ),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for IndexOutOfBoundsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use IndexOutOfBoundsError::*;

        match *self {
            Inputs { .. } | TxInput { .. } => None,
        }
    }
}

#[cfg(feature = "base64")]
mod display_from_str {
    use core::convert::Infallible;
    use core::fmt;
    use core::str::FromStr;

    use base64::display::Base64Display;
    use base64::prelude::{Engine as _, BASE64_STANDARD};
    use internals::write_err;

    use super::{Error, Psbt};

    /// Error encountered during PSBT decoding from Base64 string.
    #[derive(Debug)]
    #[non_exhaustive]
    pub enum PsbtParseError {
        /// Error in internal PSBT data structure.
        PsbtEncoding(Error),
        /// Error in PSBT Base64 encoding.
        Base64Encoding(::base64::DecodeError),
    }

    impl From<Infallible> for PsbtParseError {
        fn from(never: Infallible) -> Self { match never {} }
    }

    impl fmt::Display for PsbtParseError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            use self::PsbtParseError::*;

            match *self {
                PsbtEncoding(ref e) => write_err!(f, "error in internal PSBT data structure"; e),
                Base64Encoding(ref e) => write_err!(f, "error in PSBT base64 encoding"; e),
            }
        }
    }

    #[cfg(feature = "std")]
    impl std::error::Error for PsbtParseError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            use self::PsbtParseError::*;

            match self {
                PsbtEncoding(e) => Some(e),
                Base64Encoding(e) => Some(e),
            }
        }
    }

    impl fmt::Display for Psbt {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "{}", Base64Display::new(&self.serialize(), &BASE64_STANDARD))
        }
    }

    impl FromStr for Psbt {
        type Err = PsbtParseError;

        fn from_str(s: &str) -> Result<Self, Self::Err> {
            let data = BASE64_STANDARD.decode(s).map_err(PsbtParseError::Base64Encoding)?;
            Psbt::deserialize(&data).map_err(PsbtParseError::PsbtEncoding)
        }
    }
}
#[cfg(feature = "base64")]
pub use self::display_from_str::PsbtParseError;

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use hashes::{hash160, ripemd160, sha256};
    use hex::FromHex;
    use hex_lit::hex;
    #[cfg(feature = "rand-std")]
    use {
        crate::bip32::Fingerprint,
        crate::locktime,
        crate::script::ScriptPubKeyBufExt as _,
        secp256k1::{All, SecretKey},
    };

    use super::*;
    use crate::bip32::{ChildNumber, DerivationPath};
    use crate::locktime::absolute;
    use crate::network::NetworkKind;
    use crate::psbt::serialize::{Deserialize, Serialize};
    use crate::script::{
        RedeemScriptBuf, ScriptBufExt as _, ScriptPubKeyBuf, ScriptSigBuf, WitnessScriptBuf,
    };
    use crate::transaction::{self, OutPoint, TxIn};
    use crate::witness::Witness;
    use crate::Sequence;

    #[track_caller]
    pub fn hex_psbt(s: &str) -> Result<Psbt, crate::psbt::error::Error> {
        let r = Vec::from_hex(s);
        match r {
            Err(_e) => panic!("unable to parse hex string {}", s),
            Ok(v) => Psbt::deserialize(&v),
        }
    }

    #[track_caller]
    fn psbt_with_values(input: u64, output: u64) -> Psbt {
        Psbt {
            unsigned_tx: Transaction {
                version: transaction::Version::TWO,
                lock_time: absolute::LockTime::ZERO,
                inputs: vec![TxIn {
                    previous_output: OutPoint {
                        txid: "f61b1742ca13176464adb3cb66050c00787bb3a4eead37e985f2df1e37718126"
                            .parse()
                            .unwrap(),
                        vout: 0,
                    },
                    script_sig: ScriptSigBuf::new(),
                    sequence: Sequence::ENABLE_LOCKTIME_NO_RBF,
                    witness: Witness::default(),
                }],
                outputs: vec![TxOut {
                    value: Amount::from_sat(output).unwrap(),
                    script_pubkey: ScriptPubKeyBuf::from_hex_no_length_prefix(
                        "a9143545e6e33b832c47050f24d3eeb93c9c03948bc787",
                    )
                    .unwrap(),
                }],
            },
            xpub: Default::default(),
            version: 0,
            proprietary: BTreeMap::new(),
            unknown: BTreeMap::new(),

            inputs: vec![Input {
                witness_utxo: Some(TxOut {
                    value: Amount::from_sat(input).unwrap(),
                    script_pubkey: ScriptPubKeyBuf::from_hex_no_length_prefix(
                        "a914339725ba21efd62ac753a9bcd067d6c7a6a39d0587",
                    )
                    .unwrap(),
                }),
                ..Default::default()
            }],
            outputs: vec![],
        }
    }

    #[test]
    fn trivial_psbt() {
        let psbt = Psbt {
            unsigned_tx: Transaction {
                version: transaction::Version::TWO,
                lock_time: absolute::LockTime::ZERO,
                inputs: vec![],
                outputs: vec![],
            },
            xpub: Default::default(),
            version: 0,
            proprietary: BTreeMap::new(),
            unknown: BTreeMap::new(),

            inputs: vec![],
            outputs: vec![],
        };
        assert_eq!(psbt.serialize_hex(), "70736274ff01000a0200000000000000000000");
    }

    #[test]
    fn psbt_uncompressed_key() {
        let psbt = hex_psbt("70736274ff01003302000000010000000000000000000000000000000000000000000000000000000000000000ffffffff00ffffffff000000000000420204bb0d5d0cca36e7b9c80f63bc04c1240babb83bcd2803ef7ac8b6e2af594291daec281e856c98d210c5ab14dfd5828761f8ee7d5f45ca21ad3e4c4b41b747a3a047304402204f67e2afb76142d44fae58a2495d33a3419daa26cd0db8d04f3452b63289ac0f022010762a9fb67e94cc5cad9026f6dc99ff7f070f4278d30fbc7d0c869dd38c7fe70100").unwrap();
        assert!(psbt.inputs[0].partial_sigs.len() == 1);
        let pk = psbt.inputs[0].partial_sigs.iter().next().unwrap().0;
        assert!(!pk.compressed);
    }

    #[test]
    fn psbt_high_fee_checks() {
        let psbt = psbt_with_values(Amount::MAX.to_sat(), 1000);

        // We cannot create an expected fee rate to test against because `FeeRate::from_sat_per_mvb` is private.
        // Large fee rate errors if we pass in 1 sat/vb so just use this to get the error fee rate returned.
        let error_fee_rate = psbt
            .clone()
            .extract_tx_with_fee_rate_limit(FeeRate::from_sat_per_vb(1))
            .map_err(|e| match e {
                ExtractTxError::AbsurdFeeRate { fee_rate, .. } => fee_rate,
                _ => panic!(""),
            })
            .unwrap_err();

        // In `internal_extract_tx_with_fee_rate_limit` when we do fee / weight
        // we manually saturate to `FeeRate::MAX`.
        assert!(psbt.clone().extract_tx_with_fee_rate_limit(FeeRate::MAX).is_ok());

        // These error because the fee rate is above the limit as expected.
        assert_eq!(
            psbt.clone().extract_tx().map_err(|e| match e {
                ExtractTxError::AbsurdFeeRate { fee_rate, .. } => fee_rate,
                _ => panic!(""),
            }),
            Err(error_fee_rate)
        );
        assert_eq!(
            psbt.clone().extract_tx_fee_rate_limit().map_err(|e| match e {
                ExtractTxError::AbsurdFeeRate { fee_rate, .. } => fee_rate,
                _ => panic!(""),
            }),
            Err(error_fee_rate)
        );

        // No one is using an ~50 BTC fee so if we can handle this
        // then the `FeeRate` restrictions are fine for PSBT usage.
        let psbt = psbt_with_values(Amount::from_btc_u16(50).to_sat(), 1000); // fee = 50 BTC - 1000 sats
        assert!(psbt.extract_tx_with_fee_rate_limit(FeeRate::MAX).is_ok());

        // Testing that extract_tx will error at 25k sat/vbyte (6250000 sat/kwu)
        assert_eq!(
            psbt_with_values(2076001, 1000).extract_tx().map_err(|e| match e {
                ExtractTxError::AbsurdFeeRate { fee_rate, .. } => fee_rate,
                _ => panic!(""),
            }),
            Err(FeeRate::from_sat_per_kwu(6250003)) // 6250000 is 25k sat/vbyte
        );

        // Lowering the input satoshis by 1 lowers the sat/kwu by 3
        // Putting it exactly at 25k sat/vbyte
        assert!(psbt_with_values(2076000, 1000).extract_tx().is_ok());
    }

    #[test]
    fn serialize_then_deserialize_output() {
        let secp = &Secp256k1::new();
        let seed = hex!("000102030405060708090a0b0c0d0e0f");

        let mut hd_keypaths: BTreeMap<secp256k1::PublicKey, KeySource> = Default::default();

        let mut sk: Xpriv = Xpriv::new_master(NetworkKind::Main, &seed);

        let fprint = sk.fingerprint(secp);

        let dpath: Vec<ChildNumber> = vec![
            ChildNumber::ZERO_NORMAL,
            ChildNumber::ONE_NORMAL,
            ChildNumber::from_normal_idx(2).unwrap(),
            ChildNumber::from_normal_idx(4).unwrap(),
            ChildNumber::from_normal_idx(42).unwrap(),
            ChildNumber::from_hardened_idx(69).unwrap(),
            ChildNumber::from_normal_idx(420).unwrap(),
            ChildNumber::from_normal_idx(31337).unwrap(),
        ];

        sk = sk.derive_xpriv(secp, &dpath).unwrap();

        let pk = Xpub::from_xpriv(secp, &sk);

        hd_keypaths.insert(pk.public_key, (fprint, dpath.into()));

        let expected: Output = Output {
            redeem_script: Some(
                RedeemScriptBuf::from_hex_no_length_prefix(
                    "76a914d0c59903c5bac2868760e90fd521a4665aa7652088ac",
                )
                .unwrap(),
            ),
            witness_script: Some(
                WitnessScriptBuf::from_hex_no_length_prefix(
                    "a9143545e6e33b832c47050f24d3eeb93c9c03948bc787",
                )
                .unwrap(),
            ),
            bip32_derivation: hd_keypaths,
            ..Default::default()
        };

        let actual = Output::deserialize(&expected.serialize()).unwrap();

        assert_eq!(expected, actual);
    }

    #[test]
    fn serialize_then_deserialize_global() {
        let expected = Psbt {
            unsigned_tx: Transaction {
                version: transaction::Version::TWO,
                lock_time: absolute::LockTime::from_consensus(1257139),
                inputs: vec![TxIn {
                    previous_output: OutPoint {
                        txid: "f61b1742ca13176464adb3cb66050c00787bb3a4eead37e985f2df1e37718126"
                            .parse()
                            .unwrap(),
                        vout: 0,
                    },
                    script_sig: ScriptSigBuf::new(),
                    sequence: Sequence::ENABLE_LOCKTIME_NO_RBF,
                    witness: Witness::default(),
                }],
                outputs: vec![
                    TxOut {
                        value: Amount::from_sat_u32(99_999_699),
                        script_pubkey: ScriptPubKeyBuf::from_hex_no_length_prefix(
                            "76a914d0c59903c5bac2868760e90fd521a4665aa7652088ac",
                        )
                        .unwrap(),
                    },
                    TxOut {
                        value: Amount::from_sat_u32(100_000_000),
                        script_pubkey: ScriptPubKeyBuf::from_hex_no_length_prefix(
                            "a9143545e6e33b832c47050f24d3eeb93c9c03948bc787",
                        )
                        .unwrap(),
                    },
                ],
            },
            xpub: Default::default(),
            version: 0,
            proprietary: Default::default(),
            unknown: Default::default(),
            inputs: vec![Input::default()],
            outputs: vec![Output::default(), Output::default()],
        };

        let actual: Psbt = Psbt::deserialize(&expected.serialize()).unwrap();
        assert_eq!(expected, actual);
    }

    #[test]
    fn serialize_then_deserialize_psbtkvpair() {
        let expected = raw::Pair {
            key: raw::Key { type_value: 0u64, key_data: vec![42u8, 69u8] },
            value: vec![69u8, 42u8, 4u8],
        };

        let actual = raw::Pair::deserialize(&expected.serialize()).unwrap();

        assert_eq!(expected, actual);
    }

    #[test]
    fn deserialize_and_serialize_psbt_with_two_partial_sigs() {
        let hex = "70736274ff0100890200000001207ae985d787dfe6143d5c58fad79cc7105e0e799fcf033b7f2ba17e62d7b3200000000000ffffffff02563d03000000000022002019899534b9a011043c0dd57c3ff9a381c3522c5f27c6a42319085b56ca543a1d6adc020000000000220020618b47a07ebecca4e156edb1b9ea7c24bdee0139fc049237965ffdaf56d5ee73000000000001012b801a0600000000002200201148e93e9315e37dbed2121be5239257af35adc03ffdfc5d914b083afa44dab82202025fe7371376d53cf8a2783917c28bf30bd690b0a4d4a207690093ca2b920ee076473044022007e06b362e89912abd4661f47945430739b006a85d1b2a16c01dc1a4bd07acab022061576d7aa834988b7ab94ef21d8eebd996ea59ea20529a19b15f0c9cebe3d8ac01220202b3fe93530020a8294f0e527e33fbdff184f047eb6b5a1558a352f62c29972f8a473044022002787f926d6817504431ee281183b8119b6845bfaa6befae45e13b6d430c9d2f02202859f149a6cd26ae2f03a107e7f33c7d91730dade305fe077bae677b5d44952a01010547522102b3fe93530020a8294f0e527e33fbdff184f047eb6b5a1558a352f62c29972f8a21025fe7371376d53cf8a2783917c28bf30bd690b0a4d4a207690093ca2b920ee07652ae0001014752210283ef76537f2d58ae3aa3a4bd8ae41c3f230ccadffb1a0bd3ca504d871cff05e7210353d79cc0cb1396f4ce278d005f16d948e02a6aec9ed1109f13747ecb1507b37b52ae00010147522102b3937241777b6665e0d694e52f9c1b188433641df852da6fc42187b5d8a368a321034cdd474f01cc5aa7ff834ad8bcc882a87e854affc775486bc2a9f62e8f49bd7852ae00";
        let psbt = hex_psbt(hex).unwrap();
        assert_eq!(hex, psbt.serialize_hex());
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_psbt() {
        //! Create a full PSBT value with various fields filled and make sure it can be JSONized.
        use hashes::sha256d;

        use crate::psbt::map::Input;

        // create some values to use in the PSBT
        let tx = Transaction {
            version: transaction::Version::ONE,
            lock_time: absolute::LockTime::ZERO,
            inputs: vec![TxIn {
                previous_output: OutPoint {
                    txid: "e567952fb6cc33857f392efa3a46c995a28f69cca4bb1b37e0204dab1ec7a389"
                        .parse()
                        .unwrap(),
                    vout: 1,
                },
                script_sig: ScriptSigBuf::from_hex_no_length_prefix(
                    "160014be18d152a9b012039daf3da7de4f53349eecb985",
                )
                .unwrap(),
                sequence: Sequence::MAX,
                witness: Witness::from_slice(&[hex!(
                    "03d2e15674941bad4a996372cb87e1856d3652606d98562fe39c5e9e7e413f2105"
                )]),
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(190_303_501_938).unwrap(),
                script_pubkey: ScriptPubKeyBuf::from_hex_no_length_prefix(
                    "a914339725ba21efd62ac753a9bcd067d6c7a6a39d0587",
                )
                .unwrap(),
            }],
        };
        let unknown: BTreeMap<raw::Key, Vec<u8>> =
            vec![(raw::Key { type_value: 42, key_data: vec![0, 1] }, vec![3, 4, 5])]
                .into_iter()
                .collect();
        let key_source = ("deadbeef".parse().unwrap(), "0'/1".parse().unwrap());
        let keypaths: BTreeMap<secp256k1::PublicKey, KeySource> = vec![(
            "0339880dc92394b7355e3d0439fa283c31de7590812ea011c4245c0674a685e883".parse().unwrap(),
            key_source.clone(),
        )]
        .into_iter()
        .collect();

        let proprietary: BTreeMap<raw::ProprietaryKey, Vec<u8>> = vec![(
            raw::ProprietaryKey {
                prefix: "prefx".as_bytes().to_vec(),
                subtype: 42,
                key: "test_key".as_bytes().to_vec(),
            },
            vec![5, 6, 7],
        )]
        .into_iter()
        .collect();

        let psbt = Psbt {
            version: 0,
            xpub: {
                let xpub: Xpub =
                    "xpub661MyMwAqRbcGoRVtwfvzZsq2VBJR1LAHfQstHUoxqDorV89vRoMxUZ27kLrraAj6MPi\
                    QfrDb27gigC1VS1dBXi5jGpxmMeBXEkKkcXUTg4".parse().unwrap();
                vec![(xpub, key_source)].into_iter().collect()
            },
            unsigned_tx: {
                let mut unsigned = tx.clone();
                unsigned.inputs[0].previous_output.txid = tx.compute_txid();
                unsigned.inputs[0].script_sig = ScriptSigBuf::new();
                unsigned.inputs[0].witness = Witness::default();
                unsigned
            },
            proprietary: proprietary.clone(),
            unknown: unknown.clone(),

            inputs: vec![
                Input {
                    non_witness_utxo: Some(tx),
                    witness_utxo: Some(TxOut {
                        value: Amount::from_sat(190_303_501_938).unwrap(),
                        script_pubkey: ScriptPubKeyBuf::from_hex_no_length_prefix("a914339725ba21efd62ac753a9bcd067d6c7a6a39d0587").unwrap(),
                    }),
                    sighash_type: Some("SIGHASH_SINGLE|SIGHASH_ANYONECANPAY".parse::<PsbtSighashType>().unwrap()),
                    redeem_script: Some(vec![0x51].into()),
                    witness_script: None,
                    partial_sigs: vec![(
                        "0339880dc92394b7355e3d0439fa283c31de7590812ea011c4245c0674a685e883".parse().unwrap(),
                        "304402204f67e2afb76142d44fae58a2495d33a3419daa26cd0db8d04f3452b63289ac0f022010762a9fb67e94cc5cad9026f6dc99ff7f070f4278d30fbc7d0c869dd38c7fe701".parse().unwrap(),
                    )].into_iter().collect(),
                    bip32_derivation: keypaths.clone(),
                    final_script_witness: Some(Witness::from_slice(&[vec![1, 3], vec![5]])),
                    ripemd160_preimages: vec![(ripemd160::Hash::hash(&[1, 2]), vec![1, 2])].into_iter().collect(),
                    sha256_preimages: vec![(sha256::Hash::hash(&[1, 2]), vec![1, 2])].into_iter().collect(),
                    hash160_preimages: vec![(hash160::Hash::hash(&[1, 2]), vec![1, 2])].into_iter().collect(),
                    hash256_preimages: vec![(sha256d::Hash::hash(&[1, 2]), vec![1, 2])].into_iter().collect(),
                    proprietary: proprietary.clone(),
                    unknown: unknown.clone(),
                    ..Default::default()
                }
            ],
            outputs: vec![
                Output {
                    bip32_derivation: keypaths,
                    proprietary,
                    unknown,
                    ..Default::default()
                }
            ],
        };
        let encoded = serde_json::to_string(&psbt).unwrap();
        let decoded: Psbt = serde_json::from_str(&encoded).unwrap();
        assert_eq!(psbt, decoded);
    }

    mod bip_vectors {
        use super::*;
        use crate::psbt::map::Map;

        #[test]
        #[should_panic(expected = "InvalidMagic")]
        fn invalid_vector_1() {
            hex_psbt("0200000001268171371edff285e937adeea4b37b78000c0566cbb3ad64641713ca42171bf6000000006a473044022070b2245123e6bf474d60c5b50c043d4c691a5d2435f09a34a7662a9dc251790a022001329ca9dacf280bdf30740ec0390422422c81cb45839457aeb76fc12edd95b3012102657d118d3357b8e0f4c2cd46db7b39f6d9c38d9a70abcb9b2de5dc8dbfe4ce31feffffff02d3dff505000000001976a914d0c59903c5bac2868760e90fd521a4665aa7652088ac00e1f5050000000017a9143545e6e33b832c47050f24d3eeb93c9c03948bc787b32e1300").unwrap();
        }

        #[cfg(feature = "base64")]
        #[test]
        #[should_panic(expected = "InvalidMagic")]
        fn invalid_vector_1_base64() {
            "AgAAAAEmgXE3Ht/yhek3re6ks3t4AAwFZsuzrWRkFxPKQhcb9gAAAABqRzBEAiBwsiRRI+a/R01gxbUMBD1MaRpdJDXwmjSnZiqdwlF5CgIgATKcqdrPKAvfMHQOwDkEIkIsgctFg5RXrrdvwS7dlbMBIQJlfRGNM1e44PTCzUbbezn22cONmnCry5st5dyNv+TOMf7///8C09/1BQAAAAAZdqkU0MWZA8W6woaHYOkP1SGkZlqnZSCIrADh9QUAAAAAF6kUNUXm4zuDLEcFDyTT7rk8nAOUi8eHsy4TAA==".parse::<Psbt>().unwrap();
        }

        #[test]
        #[should_panic(expected = "ConsensusEncoding")]
        fn invalid_vector_2() {
            hex_psbt("70736274ff0100750200000001268171371edff285e937adeea4b37b78000c0566cbb3ad64641713ca42171bf60000000000feffffff02d3dff505000000001976a914d0c59903c5bac2868760e90fd521a4665aa7652088ac00e1f5050000000017a9143545e6e33b832c47050f24d3eeb93c9c03948bc787b32e1300000100fda5010100000000010289a3c71eab4d20e0371bbba4cc698fa295c9463afa2e397f8533ccb62f9567e50100000017160014be18d152a9b012039daf3da7de4f53349eecb985ffffffff86f8aa43a71dff1448893a530a7237ef6b4608bbb2dd2d0171e63aec6a4890b40100000017160014fe3e9ef1a745e974d902c4355943abcb34bd5353ffffffff0200c2eb0b000000001976a91485cff1097fd9e008bb34af709c62197b38978a4888ac72fef84e2c00000017a914339725ba21efd62ac753a9bcd067d6c7a6a39d05870247304402202712be22e0270f394f568311dc7ca9a68970b8025fdd3b240229f07f8a5f3a240220018b38d7dcd314e734c9276bd6fb40f673325bc4baa144c800d2f2f02db2765c012103d2e15674941bad4a996372cb87e1856d3652606d98562fe39c5e9e7e413f210502483045022100d12b852d85dcd961d2f5f4ab660654df6eedcc794c0c33ce5cc309ffb5fce58d022067338a8e0e1725c197fb1a88af59f51e44e4255b20167c8684031c05d1f2592a01210223b72beef0965d10be0778efecd61fcac6f79a4ea169393380734464f84f2ab30000000000")
                .unwrap();
        }

        #[cfg(feature = "base64")]
        #[test]
        #[should_panic(expected = "ConsensusEncoding")]
        fn invalid_vector_2_base64() {
            "cHNidP8BAHUCAAAAASaBcTce3/KF6Tet7qSze3gADAVmy7OtZGQXE8pCFxv2AAAAAAD+////AtPf9QUAAAAAGXapFNDFmQPFusKGh2DpD9UhpGZap2UgiKwA4fUFAAAAABepFDVF5uM7gyxHBQ8k0+65PJwDlIvHh7MuEwAAAQD9pQEBAAAAAAECiaPHHqtNIOA3G7ukzGmPopXJRjr6Ljl/hTPMti+VZ+UBAAAAFxYAFL4Y0VKpsBIDna89p95PUzSe7LmF/////4b4qkOnHf8USIk6UwpyN+9rRgi7st0tAXHmOuxqSJC0AQAAABcWABT+Pp7xp0XpdNkCxDVZQ6vLNL1TU/////8CAMLrCwAAAAAZdqkUhc/xCX/Z4Ai7NK9wnGIZeziXikiIrHL++E4sAAAAF6kUM5cluiHv1irHU6m80GfWx6ajnQWHAkcwRAIgJxK+IuAnDzlPVoMR3HyppolwuAJf3TskAinwf4pfOiQCIAGLONfc0xTnNMkna9b7QPZzMlvEuqFEyADS8vAtsnZcASED0uFWdJQbrUqZY3LLh+GFbTZSYG2YVi/jnF6efkE/IQUCSDBFAiEA0SuFLYXc2WHS9fSrZgZU327tzHlMDDPOXMMJ/7X85Y0CIGczio4OFyXBl/saiK9Z9R5E5CVbIBZ8hoQDHAXR8lkqASECI7cr7vCWXRC+B3jv7NYfysb3mk6haTkzgHNEZPhPKrMAAAAAAA==".parse::<Psbt>()
                .unwrap();
        }

        #[test]
        #[should_panic(expected = "UnsignedTxHasScriptSigs")]
        fn invalid_vector_3() {
            hex_psbt("70736274ff0100fd0a010200000002ab0949a08c5af7c49b8212f417e2f15ab3f5c33dcf153821a8139f877a5b7be4000000006a47304402204759661797c01b036b25928948686218347d89864b719e1f7fcf57d1e511658702205309eabf56aa4d8891ffd111fdf1336f3a29da866d7f8486d75546ceedaf93190121035cdc61fc7ba971c0b501a646a2a83b102cb43881217ca682dc86e2d73fa88292feffffffab0949a08c5af7c49b8212f417e2f15ab3f5c33dcf153821a8139f877a5b7be40100000000feffffff02603bea0b000000001976a914768a40bbd740cbe81d988e71de2a4d5c71396b1d88ac8e240000000000001976a9146f4620b553fa095e721b9ee0efe9fa039cca459788ac00000000000001012000e1f5050000000017a9143545e6e33b832c47050f24d3eeb93c9c03948bc787010416001485d13537f2e265405a34dbafa9e3dda01fb82308000000").unwrap();
        }

        #[cfg(feature = "base64")]
        #[test]
        #[should_panic(expected = "UnsignedTxHasScriptSigs")]
        fn invalid_vector_3_base64() {
            "cHNidP8BAP0KAQIAAAACqwlJoIxa98SbghL0F+LxWrP1wz3PFTghqBOfh3pbe+QAAAAAakcwRAIgR1lmF5fAGwNrJZKJSGhiGDR9iYZLcZ4ff89X0eURZYcCIFMJ6r9Wqk2Ikf/REf3xM286KdqGbX+EhtdVRs7tr5MZASEDXNxh/HupccC1AaZGoqg7ECy0OIEhfKaC3Ibi1z+ogpL+////qwlJoIxa98SbghL0F+LxWrP1wz3PFTghqBOfh3pbe+QBAAAAAP7///8CYDvqCwAAAAAZdqkUdopAu9dAy+gdmI5x3ipNXHE5ax2IrI4kAAAAAAAAGXapFG9GILVT+glechue4O/p+gOcykWXiKwAAAAAAAABASAA4fUFAAAAABepFDVF5uM7gyxHBQ8k0+65PJwDlIvHhwEEFgAUhdE1N/LiZUBaNNuvqePdoB+4IwgAAAA=".parse::<Psbt>().unwrap();
        }

        #[test]
        #[should_panic(expected = "MustHaveUnsignedTx")]
        fn invalid_vector_4() {
            hex_psbt("70736274ff000100fda5010100000000010289a3c71eab4d20e0371bbba4cc698fa295c9463afa2e397f8533ccb62f9567e50100000017160014be18d152a9b012039daf3da7de4f53349eecb985ffffffff86f8aa43a71dff1448893a530a7237ef6b4608bbb2dd2d0171e63aec6a4890b40100000017160014fe3e9ef1a745e974d902c4355943abcb34bd5353ffffffff0200c2eb0b000000001976a91485cff1097fd9e008bb34af709c62197b38978a4888ac72fef84e2c00000017a914339725ba21efd62ac753a9bcd067d6c7a6a39d05870247304402202712be22e0270f394f568311dc7ca9a68970b8025fdd3b240229f07f8a5f3a240220018b38d7dcd314e734c9276bd6fb40f673325bc4baa144c800d2f2f02db2765c012103d2e15674941bad4a996372cb87e1856d3652606d98562fe39c5e9e7e413f210502483045022100d12b852d85dcd961d2f5f4ab660654df6eedcc794c0c33ce5cc309ffb5fce58d022067338a8e0e1725c197fb1a88af59f51e44e4255b20167c8684031c05d1f2592a01210223b72beef0965d10be0778efecd61fcac6f79a4ea169393380734464f84f2ab30000000000").unwrap();
        }

        #[cfg(feature = "base64")]
        #[test]
        #[should_panic(expected = "MustHaveUnsignedTx")]
        fn invalid_vector_4_base64() {
            "cHNidP8AAQD9pQEBAAAAAAECiaPHHqtNIOA3G7ukzGmPopXJRjr6Ljl/hTPMti+VZ+UBAAAAFxYAFL4Y0VKpsBIDna89p95PUzSe7LmF/////4b4qkOnHf8USIk6UwpyN+9rRgi7st0tAXHmOuxqSJC0AQAAABcWABT+Pp7xp0XpdNkCxDVZQ6vLNL1TU/////8CAMLrCwAAAAAZdqkUhc/xCX/Z4Ai7NK9wnGIZeziXikiIrHL++E4sAAAAF6kUM5cluiHv1irHU6m80GfWx6ajnQWHAkcwRAIgJxK+IuAnDzlPVoMR3HyppolwuAJf3TskAinwf4pfOiQCIAGLONfc0xTnNMkna9b7QPZzMlvEuqFEyADS8vAtsnZcASED0uFWdJQbrUqZY3LLh+GFbTZSYG2YVi/jnF6efkE/IQUCSDBFAiEA0SuFLYXc2WHS9fSrZgZU327tzHlMDDPOXMMJ/7X85Y0CIGczio4OFyXBl/saiK9Z9R5E5CVbIBZ8hoQDHAXR8lkqASECI7cr7vCWXRC+B3jv7NYfysb3mk6haTkzgHNEZPhPKrMAAAAAAA==".parse::<Psbt>().unwrap();
        }

        #[test]
        #[should_panic(expected = "DuplicateKey(Key { type_value: 0, key_data: [] })")]
        fn invalid_vector_5() {
            hex_psbt("70736274ff0100750200000001268171371edff285e937adeea4b37b78000c0566cbb3ad64641713ca42171bf60000000000feffffff02d3dff505000000001976a914d0c59903c5bac2868760e90fd521a4665aa7652088ac00e1f5050000000017a9143545e6e33b832c47050f24d3eeb93c9c03948bc787b32e1300000100fda5010100000000010289a3c71eab4d20e0371bbba4cc698fa295c9463afa2e397f8533ccb62f9567e50100000017160014be18d152a9b012039daf3da7de4f53349eecb985ffffffff86f8aa43a71dff1448893a530a7237ef6b4608bbb2dd2d0171e63aec6a4890b40100000017160014fe3e9ef1a745e974d902c4355943abcb34bd5353ffffffff0200c2eb0b000000001976a91485cff1097fd9e008bb34af709c62197b38978a4888ac72fef84e2c00000017a914339725ba21efd62ac753a9bcd067d6c7a6a39d05870247304402202712be22e0270f394f568311dc7ca9a68970b8025fdd3b240229f07f8a5f3a240220018b38d7dcd314e734c9276bd6fb40f673325bc4baa144c800d2f2f02db2765c012103d2e15674941bad4a996372cb87e1856d3652606d98562fe39c5e9e7e413f210502483045022100d12b852d85dcd961d2f5f4ab660654df6eedcc794c0c33ce5cc309ffb5fce58d022067338a8e0e1725c197fb1a88af59f51e44e4255b20167c8684031c05d1f2592a01210223b72beef0965d10be0778efecd61fcac6f79a4ea169393380734464f84f2ab30000000001003f0200000001ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000ffffffff010000000000000000036a010000000000000000").unwrap();
        }

        #[cfg(feature = "base64")]
        #[test]
        #[should_panic(expected = "DuplicateKey(Key { type_value: 0, key_data: [] })")]
        fn invalid_vector_5_base64() {
            "cHNidP8BAHUCAAAAASaBcTce3/KF6Tet7qSze3gADAVmy7OtZGQXE8pCFxv2AAAAAAD+////AtPf9QUAAAAAGXapFNDFmQPFusKGh2DpD9UhpGZap2UgiKwA4fUFAAAAABepFDVF5uM7gyxHBQ8k0+65PJwDlIvHh7MuEwAAAQD9pQEBAAAAAAECiaPHHqtNIOA3G7ukzGmPopXJRjr6Ljl/hTPMti+VZ+UBAAAAFxYAFL4Y0VKpsBIDna89p95PUzSe7LmF/////4b4qkOnHf8USIk6UwpyN+9rRgi7st0tAXHmOuxqSJC0AQAAABcWABT+Pp7xp0XpdNkCxDVZQ6vLNL1TU/////8CAMLrCwAAAAAZdqkUhc/xCX/Z4Ai7NK9wnGIZeziXikiIrHL++E4sAAAAF6kUM5cluiHv1irHU6m80GfWx6ajnQWHAkcwRAIgJxK+IuAnDzlPVoMR3HyppolwuAJf3TskAinwf4pfOiQCIAGLONfc0xTnNMkna9b7QPZzMlvEuqFEyADS8vAtsnZcASED0uFWdJQbrUqZY3LLh+GFbTZSYG2YVi/jnF6efkE/IQUCSDBFAiEA0SuFLYXc2WHS9fSrZgZU327tzHlMDDPOXMMJ/7X85Y0CIGczio4OFyXBl/saiK9Z9R5E5CVbIBZ8hoQDHAXR8lkqASECI7cr7vCWXRC+B3jv7NYfysb3mk6haTkzgHNEZPhPKrMAAAAAAQA/AgAAAAH//////////////////////////////////////////wAAAAAA/////wEAAAAAAAAAAANqAQAAAAAAAAAA".parse::<Psbt>().unwrap();
        }

        #[test]
        fn valid_vector_1() {
            let unserialized = Psbt {
                unsigned_tx: Transaction {
                    version: transaction::Version::TWO,
                    lock_time: absolute::LockTime::from_consensus(1257139),
                    inputs: vec![
                        TxIn {
                            previous_output: OutPoint {
                                txid: "f61b1742ca13176464adb3cb66050c00787bb3a4eead37e985f2df1e37718126".parse().unwrap(),
                                vout: 0,
                            },
                            script_sig: ScriptSigBuf::new(),
                            sequence: Sequence::ENABLE_LOCKTIME_NO_RBF,
                            witness: Witness::default(),
                        }
                    ],
                    outputs: vec![
                        TxOut {
                            value: Amount::from_sat_u32(99_999_699),
                            script_pubkey: ScriptPubKeyBuf::from_hex_no_length_prefix("76a914d0c59903c5bac2868760e90fd521a4665aa7652088ac").unwrap(),
                        },
                        TxOut {
                            value: Amount::from_sat_u32(100_000_000),
                            script_pubkey: ScriptPubKeyBuf::from_hex_no_length_prefix("a9143545e6e33b832c47050f24d3eeb93c9c03948bc787").unwrap(),
                        },
                    ],
                },
                xpub: Default::default(),
                version: 0,
                proprietary: BTreeMap::new(),
                unknown: BTreeMap::new(),

                inputs: vec![
                    Input {
                        non_witness_utxo: Some(Transaction {
                            version: transaction::Version::ONE,
                            lock_time: absolute::LockTime::ZERO,
                            inputs: vec![
                                TxIn {
                                    previous_output: OutPoint {
                                        txid: "e567952fb6cc33857f392efa3a46c995a28f69cca4bb1b37e0204dab1ec7a389".parse().unwrap(),
                                        vout: 1,
                                    },
                                    script_sig: ScriptSigBuf::from_hex_no_length_prefix("160014be18d152a9b012039daf3da7de4f53349eecb985").unwrap(),
                                    sequence: Sequence::MAX,
                                    witness: Witness::from_slice(&[
                                        hex!("304402202712be22e0270f394f568311dc7ca9a68970b8025fdd3b240229f07f8a5f3a240220018b38d7dcd314e734c9276bd6fb40f673325bc4baa144c800d2f2f02db2765c01").as_slice(),
                                        hex!("03d2e15674941bad4a996372cb87e1856d3652606d98562fe39c5e9e7e413f2105").as_slice(),
                                    ]),
                                },
                                TxIn {
                                    previous_output: OutPoint {
                                        txid: "b490486aec3ae671012dddb2bb08466bef37720a533a894814ff1da743aaf886".parse().unwrap(),
                                        vout: 1,
                                    },
                                    script_sig: ScriptSigBuf::from_hex_no_length_prefix("160014fe3e9ef1a745e974d902c4355943abcb34bd5353").unwrap(),
                                    sequence: Sequence::MAX,
                                    witness: Witness::from_slice(&[
                                        hex!("3045022100d12b852d85dcd961d2f5f4ab660654df6eedcc794c0c33ce5cc309ffb5fce58d022067338a8e0e1725c197fb1a88af59f51e44e4255b20167c8684031c05d1f2592a01").as_slice(),
                                        hex!("0223b72beef0965d10be0778efecd61fcac6f79a4ea169393380734464f84f2ab3").as_slice(),
                                    ]),
                                }
                            ],
                            outputs: vec![
                                TxOut {
                                    value: Amount::from_sat_u32(200_000_000),
                                    script_pubkey: ScriptPubKeyBuf::from_hex_no_length_prefix("76a91485cff1097fd9e008bb34af709c62197b38978a4888ac").unwrap(),
                                },
                                TxOut {
                                    value: Amount::from_sat(190_303_501_938).unwrap(),
                                    script_pubkey: ScriptPubKeyBuf::from_hex_no_length_prefix("a914339725ba21efd62ac753a9bcd067d6c7a6a39d0587").unwrap(),
                                },
                            ],
                        }),
                        ..Default::default()
                    },
                ],
                outputs: vec![
                    Output {
                        ..Default::default()
                    },
                    Output {
                        ..Default::default()
                    },
                ],
            };

            let base16str = "70736274ff0100750200000001268171371edff285e937adeea4b37b78000c0566cbb3ad64641713ca42171bf60000000000feffffff02d3dff505000000001976a914d0c59903c5bac2868760e90fd521a4665aa7652088ac00e1f5050000000017a9143545e6e33b832c47050f24d3eeb93c9c03948bc787b32e1300000100fda5010100000000010289a3c71eab4d20e0371bbba4cc698fa295c9463afa2e397f8533ccb62f9567e50100000017160014be18d152a9b012039daf3da7de4f53349eecb985ffffffff86f8aa43a71dff1448893a530a7237ef6b4608bbb2dd2d0171e63aec6a4890b40100000017160014fe3e9ef1a745e974d902c4355943abcb34bd5353ffffffff0200c2eb0b000000001976a91485cff1097fd9e008bb34af709c62197b38978a4888ac72fef84e2c00000017a914339725ba21efd62ac753a9bcd067d6c7a6a39d05870247304402202712be22e0270f394f568311dc7ca9a68970b8025fdd3b240229f07f8a5f3a240220018b38d7dcd314e734c9276bd6fb40f673325bc4baa144c800d2f2f02db2765c012103d2e15674941bad4a996372cb87e1856d3652606d98562fe39c5e9e7e413f210502483045022100d12b852d85dcd961d2f5f4ab660654df6eedcc794c0c33ce5cc309ffb5fce58d022067338a8e0e1725c197fb1a88af59f51e44e4255b20167c8684031c05d1f2592a01210223b72beef0965d10be0778efecd61fcac6f79a4ea169393380734464f84f2ab300000000000000";

            assert_eq!(unserialized.serialize_hex(), base16str);
            assert_eq!(unserialized, hex_psbt(base16str).unwrap());

            #[cfg(feature = "base64")]
            {
                let base64str = "cHNidP8BAHUCAAAAASaBcTce3/KF6Tet7qSze3gADAVmy7OtZGQXE8pCFxv2AAAAAAD+////AtPf9QUAAAAAGXapFNDFmQPFusKGh2DpD9UhpGZap2UgiKwA4fUFAAAAABepFDVF5uM7gyxHBQ8k0+65PJwDlIvHh7MuEwAAAQD9pQEBAAAAAAECiaPHHqtNIOA3G7ukzGmPopXJRjr6Ljl/hTPMti+VZ+UBAAAAFxYAFL4Y0VKpsBIDna89p95PUzSe7LmF/////4b4qkOnHf8USIk6UwpyN+9rRgi7st0tAXHmOuxqSJC0AQAAABcWABT+Pp7xp0XpdNkCxDVZQ6vLNL1TU/////8CAMLrCwAAAAAZdqkUhc/xCX/Z4Ai7NK9wnGIZeziXikiIrHL++E4sAAAAF6kUM5cluiHv1irHU6m80GfWx6ajnQWHAkcwRAIgJxK+IuAnDzlPVoMR3HyppolwuAJf3TskAinwf4pfOiQCIAGLONfc0xTnNMkna9b7QPZzMlvEuqFEyADS8vAtsnZcASED0uFWdJQbrUqZY3LLh+GFbTZSYG2YVi/jnF6efkE/IQUCSDBFAiEA0SuFLYXc2WHS9fSrZgZU327tzHlMDDPOXMMJ/7X85Y0CIGczio4OFyXBl/saiK9Z9R5E5CVbIBZ8hoQDHAXR8lkqASECI7cr7vCWXRC+B3jv7NYfysb3mk6haTkzgHNEZPhPKrMAAAAAAAAA";
                assert_eq!(base64str.parse::<Psbt>().unwrap(), unserialized);
                assert_eq!(base64str, unserialized.to_string());
                assert_eq!(base64str.parse::<Psbt>().unwrap(), hex_psbt(base16str).unwrap());
            }
        }

        #[test]
        fn valid_vector_2() {
            let psbt = hex_psbt("70736274ff0100a00200000002ab0949a08c5af7c49b8212f417e2f15ab3f5c33dcf153821a8139f877a5b7be40000000000feffffffab0949a08c5af7c49b8212f417e2f15ab3f5c33dcf153821a8139f877a5b7be40100000000feffffff02603bea0b000000001976a914768a40bbd740cbe81d988e71de2a4d5c71396b1d88ac8e240000000000001976a9146f4620b553fa095e721b9ee0efe9fa039cca459788ac000000000001076a47304402204759661797c01b036b25928948686218347d89864b719e1f7fcf57d1e511658702205309eabf56aa4d8891ffd111fdf1336f3a29da866d7f8486d75546ceedaf93190121035cdc61fc7ba971c0b501a646a2a83b102cb43881217ca682dc86e2d73fa882920001012000e1f5050000000017a9143545e6e33b832c47050f24d3eeb93c9c03948bc787010416001485d13537f2e265405a34dbafa9e3dda01fb82308000000").unwrap();

            assert_eq!(psbt.inputs.len(), 2);
            assert_eq!(psbt.outputs.len(), 2);

            assert!(&psbt.inputs[0].final_script_sig.is_some());

            let redeem_script = psbt.inputs[1].redeem_script.as_ref().unwrap();
            let expected_out = ScriptPubKeyBuf::from_hex_no_length_prefix(
                "a9143545e6e33b832c47050f24d3eeb93c9c03948bc787",
            )
            .unwrap();

            assert!(redeem_script.is_p2wpkh());
            assert_eq!(
                redeem_script.to_p2sh().unwrap(),
                psbt.inputs[1].witness_utxo.as_ref().unwrap().script_pubkey
            );
            assert_eq!(redeem_script.to_p2sh().unwrap(), expected_out);

            for output in psbt.outputs {
                assert_eq!(output.get_pairs().len(), 0)
            }
        }

        #[test]
        fn valid_vector_3() {
            let psbt = hex_psbt("70736274ff0100750200000001268171371edff285e937adeea4b37b78000c0566cbb3ad64641713ca42171bf60000000000feffffff02d3dff505000000001976a914d0c59903c5bac2868760e90fd521a4665aa7652088ac00e1f5050000000017a9143545e6e33b832c47050f24d3eeb93c9c03948bc787b32e1300000100fda5010100000000010289a3c71eab4d20e0371bbba4cc698fa295c9463afa2e397f8533ccb62f9567e50100000017160014be18d152a9b012039daf3da7de4f53349eecb985ffffffff86f8aa43a71dff1448893a530a7237ef6b4608bbb2dd2d0171e63aec6a4890b40100000017160014fe3e9ef1a745e974d902c4355943abcb34bd5353ffffffff0200c2eb0b000000001976a91485cff1097fd9e008bb34af709c62197b38978a4888ac72fef84e2c00000017a914339725ba21efd62ac753a9bcd067d6c7a6a39d05870247304402202712be22e0270f394f568311dc7ca9a68970b8025fdd3b240229f07f8a5f3a240220018b38d7dcd314e734c9276bd6fb40f673325bc4baa144c800d2f2f02db2765c012103d2e15674941bad4a996372cb87e1856d3652606d98562fe39c5e9e7e413f210502483045022100d12b852d85dcd961d2f5f4ab660654df6eedcc794c0c33ce5cc309ffb5fce58d022067338a8e0e1725c197fb1a88af59f51e44e4255b20167c8684031c05d1f2592a01210223b72beef0965d10be0778efecd61fcac6f79a4ea169393380734464f84f2ab30000000001030401000000000000").unwrap();

            assert_eq!(psbt.inputs.len(), 1);
            assert_eq!(psbt.outputs.len(), 2);

            let tx_input = &psbt.unsigned_tx.inputs[0];
            let psbt_non_witness_utxo = psbt.inputs[0].non_witness_utxo.as_ref().unwrap();

            assert_eq!(tx_input.previous_output.txid, psbt_non_witness_utxo.compute_txid());
            assert!(psbt_non_witness_utxo.outputs[tx_input.previous_output.vout as usize]
                .script_pubkey
                .is_p2pkh());
            assert_eq!(
                psbt.inputs[0].sighash_type.as_ref().unwrap().ecdsa_hash_ty().unwrap(),
                EcdsaSighashType::All
            );
        }

        #[test]
        fn valid_vector_4() {
            let psbt = hex_psbt("70736274ff0100a00200000002ab0949a08c5af7c49b8212f417e2f15ab3f5c33dcf153821a8139f877a5b7be40000000000feffffffab0949a08c5af7c49b8212f417e2f15ab3f5c33dcf153821a8139f877a5b7be40100000000feffffff02603bea0b000000001976a914768a40bbd740cbe81d988e71de2a4d5c71396b1d88ac8e240000000000001976a9146f4620b553fa095e721b9ee0efe9fa039cca459788ac00000000000100df0200000001268171371edff285e937adeea4b37b78000c0566cbb3ad64641713ca42171bf6000000006a473044022070b2245123e6bf474d60c5b50c043d4c691a5d2435f09a34a7662a9dc251790a022001329ca9dacf280bdf30740ec0390422422c81cb45839457aeb76fc12edd95b3012102657d118d3357b8e0f4c2cd46db7b39f6d9c38d9a70abcb9b2de5dc8dbfe4ce31feffffff02d3dff505000000001976a914d0c59903c5bac2868760e90fd521a4665aa7652088ac00e1f5050000000017a9143545e6e33b832c47050f24d3eeb93c9c03948bc787b32e13000001012000e1f5050000000017a9143545e6e33b832c47050f24d3eeb93c9c03948bc787010416001485d13537f2e265405a34dbafa9e3dda01fb8230800220202ead596687ca806043edc3de116cdf29d5e9257c196cd055cf698c8d02bf24e9910b4a6ba670000008000000080020000800022020394f62be9df19952c5587768aeb7698061ad2c4a25c894f47d8c162b4d7213d0510b4a6ba6700000080010000800200008000").unwrap();

            assert_eq!(psbt.inputs.len(), 2);
            assert_eq!(psbt.outputs.len(), 2);

            assert!(&psbt.inputs[0].final_script_sig.is_none());
            assert!(&psbt.inputs[1].final_script_sig.is_none());

            let redeem_script = psbt.inputs[1].redeem_script.as_ref().unwrap();
            let expected_out = ScriptPubKeyBuf::from_hex_no_length_prefix(
                "a9143545e6e33b832c47050f24d3eeb93c9c03948bc787",
            )
            .unwrap();

            assert!(redeem_script.is_p2wpkh());
            assert_eq!(
                redeem_script.to_p2sh().unwrap(),
                psbt.inputs[1].witness_utxo.as_ref().unwrap().script_pubkey
            );
            assert_eq!(redeem_script.to_p2sh().unwrap(), expected_out);

            for output in psbt.outputs {
                assert!(!output.get_pairs().is_empty())
            }
        }

        #[test]
        fn valid_vector_5() {
            let psbt = hex_psbt("70736274ff0100550200000001279a2323a5dfb51fc45f220fa58b0fc13e1e3342792a85d7e36cd6333b5cbc390000000000ffffffff01a05aea0b000000001976a914ffe9c0061097cc3b636f2cb0460fa4fc427d2b4588ac0000000000010120955eea0b0000000017a9146345200f68d189e1adc0df1c4d16ea8f14c0dbeb87220203b1341ccba7683b6af4f1238cd6e97e7167d569fac47f1e48d47541844355bd4646304302200424b58effaaa694e1559ea5c93bbfd4a89064224055cdf070b6771469442d07021f5c8eb0fea6516d60b8acb33ad64ede60e8785bfb3aa94b99bdf86151db9a9a010104220020771fd18ad459666dd49f3d564e3dbc42f4c84774e360ada16816a8ed488d5681010547522103b1341ccba7683b6af4f1238cd6e97e7167d569fac47f1e48d47541844355bd462103de55d1e1dac805e3f8a58c1fbf9b94c02f3dbaafe127fefca4995f26f82083bd52ae220603b1341ccba7683b6af4f1238cd6e97e7167d569fac47f1e48d47541844355bd4610b4a6ba67000000800000008004000080220603de55d1e1dac805e3f8a58c1fbf9b94c02f3dbaafe127fefca4995f26f82083bd10b4a6ba670000008000000080050000800000").unwrap();

            assert_eq!(psbt.inputs.len(), 1);
            assert_eq!(psbt.outputs.len(), 1);

            assert!(&psbt.inputs[0].final_script_sig.is_none());

            let redeem_script = psbt.inputs[0].redeem_script.as_ref().unwrap();
            let expected_out = ScriptPubKeyBuf::from_hex_no_length_prefix(
                "a9146345200f68d189e1adc0df1c4d16ea8f14c0dbeb87",
            )
            .unwrap();

            assert!(redeem_script.is_p2wsh());
            assert_eq!(
                redeem_script.to_p2sh().unwrap(),
                psbt.inputs[0].witness_utxo.as_ref().unwrap().script_pubkey
            );

            assert_eq!(redeem_script.to_p2sh().unwrap(), expected_out);
        }

        #[test]
        fn valid_vector_6() {
            let psbt = hex_psbt("70736274ff01003f0200000001ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000ffffffff010000000000000000036a010000000000000a0f0102030405060708090f0102030405060708090a0b0c0d0e0f0000").unwrap();

            assert_eq!(psbt.inputs.len(), 1);
            assert_eq!(psbt.outputs.len(), 1);

            let tx = &psbt.unsigned_tx;
            assert_eq!(
                tx.compute_txid(),
                "75c5c9665a570569ad77dd1279e6fd4628a093c4dcbf8d41532614044c14c115".parse().unwrap(),
            );

            let mut unknown: BTreeMap<raw::Key, Vec<u8>> = BTreeMap::new();
            let key: raw::Key =
                raw::Key { type_value: 0x0fu64, key_data: hex!("010203040506070809").to_vec() };
            let value = hex!("0102030405060708090a0b0c0d0e0f").to_vec();

            unknown.insert(key, value);

            assert_eq!(psbt.inputs[0].unknown, unknown)
        }
    }

    // BIP-371 (Taproot) PSBT test vectors removed - BCH does not support Taproot.

    #[test]
    fn invalid_vector_4617() {
        let err = hex_psbt("70736274ff01007374ff0103010000000000000000002e2873007374ff0107736205000000000000000000000000000000000006060005feffffff74ff01000a000000000000002cc760008530b38dac0100030500000074ff01070100000000000000000000000000c0316888e006000600050000736274ff00d90001007374ff41030100000000000a0a06002e2873007374ff01070100000000000000000000000000000000ff0000060600050000736274ff01000a0080000000000024c7600005193b1e400700030500000074ff0107010000000000a9c7df3f07000570ed62c76004c3ca95c5f90200010742420a0a000000000000").unwrap_err();
        match err {
            Error::IncorrectNonWitnessUtxo { index: 0, input_outpoint, non_witness_utxo_txid } => {
                assert_eq!(
                    input_outpoint,
                    "00000000000000000000000562730701ff74730073282e000000000000000000:0"
                        .parse()
                        .unwrap(),
                );
                assert_eq!(
                    non_witness_utxo_txid,
                    "9ed45fd3f73b038649bee6e763dbd70868745c48a0d2b0299f42c68f957995f4"
                        .parse()
                        .unwrap(),
                );
            }
            _ => panic!("expected output hash mismatch error, got {}", err),
        }
    }

    #[test]
    fn serialize_and_deserialize_preimage_psbt() {
        // create a sha preimage map
        let mut sha256_preimages = BTreeMap::new();
        sha256_preimages.insert(sha256::Hash::hash(&[1u8, 2u8]), vec![1u8, 2u8]);
        sha256_preimages.insert(sha256::Hash::hash(&[1u8]), vec![1u8]);

        // same for hash160
        let mut hash160_preimages = BTreeMap::new();
        hash160_preimages.insert(hash160::Hash::hash(&[1u8, 2u8]), vec![1u8, 2u8]);
        hash160_preimages.insert(hash160::Hash::hash(&[1u8]), vec![1u8]);

        // same vector as valid_vector_1 from BIPs with added
        let mut unserialized = Psbt {
            unsigned_tx: Transaction {
                version: transaction::Version::TWO,
                lock_time: absolute::LockTime::from_consensus(1257139),
                inputs: vec![
                    TxIn {
                        previous_output: OutPoint {
                            txid: "f61b1742ca13176464adb3cb66050c00787bb3a4eead37e985f2df1e37718126".parse().unwrap(),
                            vout: 0,
                        },
                        script_sig: ScriptSigBuf::new(),
                        sequence: Sequence::ENABLE_LOCKTIME_NO_RBF,
                        witness: Witness::default(),
                    }
                ],
                outputs: vec![
                    TxOut {
                        value: Amount::from_sat_u32(99_999_699),
                        script_pubkey: ScriptPubKeyBuf::from_hex_no_length_prefix("76a914d0c59903c5bac2868760e90fd521a4665aa7652088ac").unwrap(),
                    },
                    TxOut {
                        value: Amount::from_sat_u32(100_000_000),
                        script_pubkey: ScriptPubKeyBuf::from_hex_no_length_prefix("a9143545e6e33b832c47050f24d3eeb93c9c03948bc787").unwrap(),
                    },
                ],
            },
            version: 0,
            xpub: Default::default(),
            proprietary: Default::default(),
            unknown: BTreeMap::new(),

            inputs: vec![
                Input {
                    non_witness_utxo: Some(Transaction {
                        version: transaction::Version::ONE,
                        lock_time: absolute::LockTime::ZERO,
                        inputs: vec![
                            TxIn {
                                previous_output: OutPoint {
                                    txid: "e567952fb6cc33857f392efa3a46c995a28f69cca4bb1b37e0204dab1ec7a389".parse().unwrap(),
                                    vout: 1,
                                },
                                script_sig: ScriptSigBuf::from_hex_no_length_prefix("160014be18d152a9b012039daf3da7de4f53349eecb985").unwrap(),
                                sequence: Sequence::MAX,
                                witness: Witness::from_slice(&[
                                    hex!("304402202712be22e0270f394f568311dc7ca9a68970b8025fdd3b240229f07f8a5f3a240220018b38d7dcd314e734c9276bd6fb40f673325bc4baa144c800d2f2f02db2765c01").as_slice(),
                                    hex!("03d2e15674941bad4a996372cb87e1856d3652606d98562fe39c5e9e7e413f2105").as_slice(),
                                ]),
                            },
                            TxIn {
                                previous_output: OutPoint {
                                    txid: "b490486aec3ae671012dddb2bb08466bef37720a533a894814ff1da743aaf886".parse().unwrap(),
                                    vout: 1,
                                },
                                script_sig: ScriptSigBuf::from_hex_no_length_prefix("160014fe3e9ef1a745e974d902c4355943abcb34bd5353").unwrap(),
                                sequence: Sequence::MAX,
                                witness: Witness::from_slice(&[
                                    hex!("3045022100d12b852d85dcd961d2f5f4ab660654df6eedcc794c0c33ce5cc309ffb5fce58d022067338a8e0e1725c197fb1a88af59f51e44e4255b20167c8684031c05d1f2592a01").as_slice(),
                                    hex!("0223b72beef0965d10be0778efecd61fcac6f79a4ea169393380734464f84f2ab3").as_slice(),
                                ]),
                            }
                        ],
                        outputs: vec![
                            TxOut {
                                value: Amount::from_sat_u32(200_000_000),
                                script_pubkey: ScriptPubKeyBuf::from_hex_no_length_prefix("76a91485cff1097fd9e008bb34af709c62197b38978a4888ac").unwrap(),
                            },
                            TxOut {
                                value: Amount::from_sat(190_303_501_938).unwrap(),
                                script_pubkey: ScriptPubKeyBuf::from_hex_no_length_prefix("a914339725ba21efd62ac753a9bcd067d6c7a6a39d0587").unwrap(),
                            },
                        ],
                    }),
                    ..Default::default()
                },
            ],
            outputs: vec![
                Output {
                    ..Default::default()
                },
                Output {
                    ..Default::default()
                },
            ],
        };
        unserialized.inputs[0].hash160_preimages = hash160_preimages;
        unserialized.inputs[0].sha256_preimages = sha256_preimages;

        let rtt = hex_psbt(&unserialized.serialize_hex()).unwrap();
        assert_eq!(rtt, unserialized);

        // Now add an ripemd160 with incorrect preimage
        let mut ripemd160_preimages = BTreeMap::new();
        ripemd160_preimages.insert(ripemd160::Hash::hash(&[17u8]), vec![18u8]);
        unserialized.inputs[0].ripemd160_preimages = ripemd160_preimages;

        // Now the roundtrip should fail as the preimage is incorrect.
        let rtt: Result<Psbt, _> = hex_psbt(&unserialized.serialize_hex());
        assert!(rtt.is_err());
    }

    #[test]
    fn serialize_and_deserialize_proprietary() {
        let mut psbt = hex_psbt("70736274ff0100a00200000002ab0949a08c5af7c49b8212f417e2f15ab3f5c33dcf153821a8139f877a5b7be40000000000feffffffab0949a08c5af7c49b8212f417e2f15ab3f5c33dcf153821a8139f877a5b7be40100000000feffffff02603bea0b000000001976a914768a40bbd740cbe81d988e71de2a4d5c71396b1d88ac8e240000000000001976a9146f4620b553fa095e721b9ee0efe9fa039cca459788ac000000000001076a47304402204759661797c01b036b25928948686218347d89864b719e1f7fcf57d1e511658702205309eabf56aa4d8891ffd111fdf1336f3a29da866d7f8486d75546ceedaf93190121035cdc61fc7ba971c0b501a646a2a83b102cb43881217ca682dc86e2d73fa882920001012000e1f5050000000017a9143545e6e33b832c47050f24d3eeb93c9c03948bc787010416001485d13537f2e265405a34dbafa9e3dda01fb82308000000").unwrap();
        psbt.proprietary.insert(
            raw::ProprietaryKey { prefix: b"test".to_vec(), subtype: 0u64, key: b"test".to_vec() },
            b"test".to_vec(),
        );
        assert!(!psbt.proprietary.is_empty());
        let rtt = hex_psbt(&psbt.serialize_hex()).unwrap();
        assert!(!rtt.proprietary.is_empty());
    }

    // PSBTs taken from BIP 174 test vectors.
    #[test]
    fn combine_psbts() {
        let mut psbt1 = hex_psbt(include_str!("../../tests/data/psbt1.hex")).unwrap();
        let psbt2 = hex_psbt(include_str!("../../tests/data/psbt2.hex")).unwrap();
        let psbt_combined = hex_psbt(include_str!("../../tests/data/psbt2.hex")).unwrap();

        psbt1.combine(psbt2).expect("psbt combine to succeed");
        assert_eq!(psbt1, psbt_combined);
    }

    #[test]
    fn combine_psbts_commutative() {
        let mut psbt1 = hex_psbt(include_str!("../../tests/data/psbt1.hex")).unwrap();
        let mut psbt2 = hex_psbt(include_str!("../../tests/data/psbt2.hex")).unwrap();

        let psbt1_clone = psbt1.clone();
        let psbt2_clone = psbt2.clone();

        psbt1.combine(psbt2_clone).expect("psbt1 combine to succeed");
        psbt2.combine(psbt1_clone).expect("psbt2 combine to succeed");

        assert_eq!(psbt1, psbt2);
    }

    // https://github.com/rust-bitcoin/rust-bitcoin/issues/3628
    #[test]
    fn combine_psbt_fuzz_3628() {
        let mut psbt1 = hex_psbt(include_str!("../../tests/data/psbt_fuzz1.hex")).unwrap();
        let psbt2 = hex_psbt(include_str!("../../tests/data/psbt_fuzz2.hex")).unwrap();

        assert!(matches!(
            psbt1.combine(psbt2).unwrap_err(),
            Error::CombineInconsistentKeySources(_)
        ));
    }

    #[cfg(feature = "rand-std")]
    fn gen_keys() -> (PrivateKey, PublicKey, Secp256k1<All>) {
        use secp256k1::rand::thread_rng;

        let secp = Secp256k1::new();

        let sk = SecretKey::new(&mut thread_rng());
        let priv_key = PrivateKey::new(sk, NetworkKind::Test);
        let pk = PublicKey::from_private_key(&secp, priv_key);

        (priv_key, pk, secp)
    }

    #[test]
    #[cfg(feature = "rand-std")]
    fn get_key_btree_map() {
        let (priv_key, pk, secp) = gen_keys();

        let mut key_map = BTreeMap::new();
        key_map.insert(pk, priv_key);

        let got = key_map.get_key(&KeyRequest::Pubkey(pk), &secp).expect("failed to get key");
        assert_eq!(got.unwrap(), priv_key)
    }

    #[test]
    fn get_key_xpriv_bip32_parent() {
        let secp = Secp256k1::new();

        let seed = hex!("000102030405060708090a0b0c0d0e0f");
        let parent_xpriv: Xpriv = Xpriv::new_master(NetworkKind::Main, &seed);
        let path: DerivationPath = "m/1/2/3".parse().unwrap();
        let path_prefix: DerivationPath = "m/1".parse().unwrap();

        let expected_private_key =
            parent_xpriv.derive_xpriv(&secp, &path).unwrap().to_private_key();

        let derived_xpriv = parent_xpriv.derive_xpriv(&secp, &path_prefix).unwrap();

        let derived_key = derived_xpriv
            .get_key(&KeyRequest::Bip32((parent_xpriv.fingerprint(&secp), path.clone())), &secp)
            .unwrap();

        assert_eq!(derived_key, Some(expected_private_key));
    }

    #[test]
    fn fee() {
        let output_0_val = Amount::from_sat_u32(99_999_699);
        let output_1_val = Amount::from_sat_u32(100_000_000);
        let prev_output_val = Amount::from_sat_u32(200_000_000);

        let t = Psbt {
            unsigned_tx: Transaction {
                version: transaction::Version::TWO,
                lock_time: absolute::LockTime::from_consensus(1257139),
                inputs: vec![
                    TxIn {
                        previous_output: OutPoint {
                            txid: "f61b1742ca13176464adb3cb66050c00787bb3a4eead37e985f2df1e37718126".parse().unwrap(),
                            vout: 0,
                        },
                        sequence: Sequence::ENABLE_LOCKTIME_NO_RBF,
                        ..TxIn::EMPTY_COINBASE
                    }
                ],
                outputs: vec![
                    TxOut {
                        value: output_0_val,
                        script_pubkey: ScriptPubKeyBuf::new()
                    },
                    TxOut {
                        value: output_1_val,
                        script_pubkey: ScriptPubKeyBuf::new()
                    },
                ],
            },
            xpub: Default::default(),
            version: 0,
            proprietary: BTreeMap::new(),
            unknown: BTreeMap::new(),

            inputs: vec![
                Input {
                    non_witness_utxo: Some(Transaction {
                        version: transaction::Version::ONE,
                        lock_time: absolute::LockTime::ZERO,
                        inputs: vec![
                            TxIn {
                                previous_output: OutPoint {
                                    txid: "e567952fb6cc33857f392efa3a46c995a28f69cca4bb1b37e0204dab1ec7a389".parse().unwrap(),
                                    vout: 1,
                                },
                                sequence: Sequence::MAX,
                                ..TxIn::EMPTY_COINBASE
                            },
                            TxIn {
                                previous_output: OutPoint {
                                    txid: "b490486aec3ae671012dddb2bb08466bef37720a533a894814ff1da743aaf886".parse().unwrap(),
                                    vout: 1,
                                },
                                sequence: Sequence::MAX,
                                ..TxIn::EMPTY_COINBASE
                            }
                        ],
                        outputs: vec![
                            TxOut {
                                value: prev_output_val,
                                script_pubkey:  ScriptPubKeyBuf::new()
                            },
                            TxOut {
                                value: Amount::from_sat(190_303_501_938).unwrap(),
                                script_pubkey:  ScriptPubKeyBuf::new()
                            },
                        ],
                    }),
                    ..Default::default()
                },
            ],
            outputs: vec![
                Output {
                    ..Default::default()
                },
                Output {
                    ..Default::default()
                },
            ],
        };
        assert_eq!(
            t.fee().expect("fee calculation"),
            (prev_output_val - (output_0_val + output_1_val)).unwrap()
        );
        // no previous output
        let mut t2 = t.clone();
        t2.inputs[0].non_witness_utxo = None;
        match t2.fee().unwrap_err() {
            Error::MissingUtxo => {}
            e => panic!("unexpected error: {:?}", e),
        }
        //  negative fee
        let mut t3 = t.clone();
        t3.unsigned_tx.outputs[0].value = prev_output_val;
        match t3.fee().unwrap_err() {
            Error::NegativeFee => {}
            e => panic!("unexpected error: {:?}", e),
        }
    }

}
