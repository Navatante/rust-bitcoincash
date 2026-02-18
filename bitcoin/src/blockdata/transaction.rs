// SPDX-License-Identifier: CC0-1.0

//! Bitcoin transactions.
//!
//! A transaction describes a transfer of money. It consumes previously-unspent
//! transaction outputs and produces new ones, satisfying the condition to spend
//! the old outputs (typically a digital signature with a specific key must be
//! provided) and defining the condition to spend the new ones. The use of digital
//! signatures ensures that coins cannot be spent by unauthorized parties.
//!
//! This module provides the structures and functions needed to support transactions.

use core::fmt;

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};
use internals::{compact_size, const_casts, write_err, ToU64};
use io::{BufRead, Write};

use super::Weight;
use crate::consensus::{self, encode, Decodable, Encodable};
use crate::locktime::absolute::{self, Height, MedianTimePast};
use crate::prelude::{Borrow, Vec};
use crate::script::{
    RedeemScript, ScriptExt as _, ScriptExtPriv as _, ScriptPubKey, ScriptPubKeyBuf,
    ScriptPubKeyExt as _,
};
#[cfg(doc)]
use crate::sighash::EcdsaSighashType;
use crate::{internal_macros, Amount, FeeRate, Sequence, SignedAmount};

#[rustfmt::skip]            // Keep public re-exports separate.
#[doc(inline)]
pub use primitives::transaction::{OutPoint, ParseOutPointError, Transaction, Ntxid, Txid, Wtxid, Version, TxIn, TxOut};

internal_macros::impl_hashencode!(Txid);
internal_macros::impl_hashencode!(Wtxid);

internal_macros::define_extension_trait! {
    /// Extension functionality for the [`Txid`] type.
    pub trait TxidExt impl for Txid {
        /// The "all zeros" TXID.
        #[deprecated(since = "TBD", note = "use `Txid::COINBASE_PREVOUT` instead")]
        fn all_zeros() -> Self { Self::COINBASE_PREVOUT }
    }
}

internal_macros::define_extension_trait! {
    /// Extension functionality for the [`Wtxid`] type.
    pub trait WtxidExt impl for Wtxid {
        /// The "all zeros" wTXID.
        #[deprecated(since = "TBD", note = "use `Wtxid::COINBASE` instead")]
        fn all_zeros() -> Self { Self::COINBASE }
    }
}

/// Trait that abstracts over a transaction identifier i.e., `Txid` and `Wtxid`.
pub trait TxIdentifier: sealed::Sealed + AsRef<[u8]> {}

impl TxIdentifier for Txid {}
impl TxIdentifier for Wtxid {}


internal_macros::define_extension_trait! {
    /// Extension functionality for the [`OutPoint`] type.
    pub trait OutPointExt impl for OutPoint {
        /// Constructs a new [`OutPoint`].
        #[inline]
        #[deprecated(since = "TBD", note = "use struct initialization syntax instead")]
        #[allow(clippy::new-ret-no-self)]
        fn new(txid: Txid, vout: u32) -> Self { OutPoint { txid, vout } }

        /// Checks if an `OutPoint` is "null".
        #[inline]
        #[deprecated(since = "TBD", note = "use `outpoint == OutPoint::COINBASE_PREVOUT` instead")]
        fn is_null(&self) -> bool { *self == OutPoint::COINBASE_PREVOUT }
    }
}

/// Returns the input base weight.
///
/// Base weight excludes the witness and script.
// We need to use this const here but do not want to make it public in `primitives::TxIn`.
const TX_IN_BASE_WEIGHT: Weight =
    Weight::from_vb_unchecked(OutPoint::SIZE as u64 + Sequence::SIZE as u64);

internal_macros::define_extension_trait! {
    /// Extension functionality for the [`TxIn`] type.
    pub trait TxInExt impl for TxIn {
        /// Returns true if this input enables the [`absolute::LockTime`] (aka `nLockTime`) of its
        /// [`Transaction`].
        ///
        /// `nLockTime` is enabled if *any* input enables it. See [`Transaction::is_lock_time_enabled`]
        ///  to check the overall state. If none of the inputs enables it, the lock time value is simply
        ///  ignored. If this returns false and OP_CHECKLOCKTIMEVERIFY is used in the redeem script with
        ///  this input then the script execution will fail [BIP-0065].
        ///
        /// [BIP-0065](https://github.com/bitcoin/bips/blob/master/bip-0065.mediawiki)
        fn enables_lock_time(&self) -> bool { self.sequence != Sequence::MAX }

        /// The weight of this input.
        ///
        /// In Bitcoin Cash there is no witness discount, so weight equals base size * 4.
        ///
        /// Keep in mind that when adding a TxIn to a transaction, the total weight of the transaction
        /// might increase more than this value. This happens when the new input added causes
        /// the input length `CompactSize` to increase its encoding length.
        fn legacy_weight(&self) -> Weight {
            Weight::from_non_witness_data_size(self.base_size().to_u64())
        }

        /// Returns the base size of this input.
        fn base_size(&self) -> usize {
            let mut size = OutPoint::SIZE;

            size += compact_size::encoded_size(self.script_sig.len());
            size += self.script_sig.len();

            size + Sequence::SIZE
        }

        /// Returns the total number of bytes that this input contributes to a transaction.
        fn total_size(&self) -> usize { self.base_size() }
    }
}

internal_macros::define_extension_trait! {
    /// Extension functionality for the [`TxOut`] type.
    pub trait TxOutExt impl for TxOut {
        /// The weight of this output.
        ///
        /// Keep in mind that when adding a [`TxOut`] to a [`Transaction`] the total weight of the
        /// transaction might increase more than `TxOut::weight`. This happens when the new output added
        /// causes the output length `CompactSize` to increase its encoding length.
        ///
        /// # Panics
        ///
        /// If output size * 4 overflows, this should never happen under normal conditions. Use
        /// `Weight::from_vb_checked(self.size() as u64)` if you are concerned.
        fn weight(&self) -> Weight {
            // Size is equivalent to virtual size since all bytes of a TxOut are non-witness bytes.
            Weight::from_vb(self.size().to_u64())
                .expect("should never happen under normal conditions")
        }

        /// Returns the total number of bytes that this output contributes to a transaction.
        ///
        /// There is no difference between base size vs total size for outputs.
        fn size(&self) -> usize { size_from_script_pubkey(&self.script_pubkey) }

        /// Constructs a new `TxOut` with given script and the smallest possible `value` that is **not** dust
        /// per current Core policy.
        ///
        /// Dust depends on the -dustrelayfee value of the Bitcoin Core node you are broadcasting to.
        /// This function uses the default value of 0.00003 BTC/kB (3 sat/vByte).
        ///
        /// To use a custom value, use [`minimal_non_dust_custom`].
        ///
        /// [`minimal_non_dust_custom`]: TxOut::minimal_non_dust_custom
        fn minimal_non_dust(script_pubkey: ScriptPubKeyBuf) -> TxOut {
            TxOut { value: script_pubkey.minimal_non_dust(), script_pubkey }
        }

        /// Constructs a new `TxOut` with given script and the smallest possible `value` that is **not** dust
        /// per current Core policy.
        ///
        /// Dust depends on the -dustrelayfee value of the Bitcoin Core node you are broadcasting to.
        /// This function lets you set the fee rate used in dust calculation.
        ///
        /// The current default value in Bitcoin Core (as of v26) is 3 sat/vByte.
        ///
        /// To use the default Bitcoin Core value, use [`minimal_non_dust`].
        ///
        /// [`minimal_non_dust`]: TxOut::minimal_non_dust
        fn minimal_non_dust_custom(script_pubkey: ScriptPubKeyBuf, dust_relay_fee: FeeRate) -> Option<TxOut> {
            Some(TxOut { value: script_pubkey.minimal_non_dust_custom(dust_relay_fee)?, script_pubkey })
        }
    }
}

/// Returns the total number of bytes that this script pubkey would contribute to a transaction.
fn size_from_script_pubkey(script_pubkey: &ScriptPubKey) -> usize {
    let len = script_pubkey.len();
    Amount::SIZE + compact_size::encoded_size(len) + len
}

/// Extension functionality for the [`Transaction`] type.
pub trait TransactionExt: sealed::Sealed {
    /// Computes a "normalized TXID" which does not include any signatures.
    #[deprecated(since = "0.31.0", note = "use `compute_ntxid()` instead")]
    fn ntxid(&self) -> Ntxid;

    /// Computes the [`Txid`].
    #[deprecated(since = "0.31.0", note = "use `compute_txid()` instead")]
    fn txid(&self) -> Txid;

    /// Computes the SegWit version of the transaction id.
    #[deprecated(since = "0.31.0", note = "use `compute_wtxid()` instead")]
    fn wtxid(&self) -> Wtxid;

    /// Returns the weight of this transaction.
    ///
    /// In Bitcoin Cash, weight equals total size * 4 (no witness discount).
    fn weight(&self) -> Weight;

    /// Returns the base transaction size (same as total size in BCH - no witness data).
    fn base_size(&self) -> usize;

    /// Returns the total transaction size.
    fn total_size(&self) -> usize;

    /// Returns the "virtual size" (vsize) of this transaction.
    ///
    /// In Bitcoin Cash, vsize equals the serialized size (weight / 4 = size since weight = size * 4).
    fn vsize(&self) -> usize;

    /// Checks if this is a coinbase transaction.
    ///
    /// The first transaction in the block distributes the mining reward and is called the coinbase
    /// transaction. It is impossible to check if the transaction is first in the block, so this
    /// function checks the structure of the transaction instead - the previous output must be
    /// all-zeros (creates satoshis "out of thin air").
    #[doc(alias = "is_coin_base")] // method previously had this name
    fn is_coinbase(&self) -> bool;

    /// Returns `true` if the transaction itself opted in to be BIP-0125-replaceable (RBF).
    ///
    /// # Warning
    ///
    /// **Incorrectly relying on RBF may lead to monetary loss!**
    ///
    /// This **does not** cover the case where a transaction becomes replaceable due to ancestors
    /// being RBF. Please note that transactions **may be replaced** even if they **do not** include
    /// the RBF signal: <https://bitcoinops.org/en/newsletters/2022/10/19/#transaction-replacement-option>.
    fn is_explicitly_rbf(&self) -> bool;

    /// Returns true if this [`Transaction`]'s absolute timelock is satisfied at `height`/`time`.
    ///
    /// # Returns
    ///
    /// By definition if the lock time is not enabled the transaction's absolute timelock is
    /// considered to be satisfied i.e., there are no timelock constraints restricting this
    /// transaction from being mined immediately.
    fn is_absolute_timelock_satisfied(&self, height: Height, time: MedianTimePast) -> bool;

    /// Returns `true` if this transactions nLockTime is enabled ([BIP-0065]).
    ///
    /// [BIP-0065]: https://github.com/bitcoin/bips/blob/master/bip-0065.mediawiki
    fn is_lock_time_enabled(&self) -> bool;

    /// Returns an iterator over lengths of `script_pubkey`s in the outputs.
    ///
    /// This is useful in combination with [`predict_weight`] if you have the transaction already
    /// constructed with a dummy value in the fee output which you'll adjust after calculating the
    /// weight.
    fn script_pubkey_lens(&self) -> TxOutToScriptPubkeyLengthIter<'_>;

    /// Counts the total number of sigops.
    ///
    /// This value is for pre-Taproot transactions only.
    ///
    /// > In Taproot, a different mechanism is used. Instead of having a global per-block limit,
    /// > there is a per-transaction-input limit, proportional to the size of that input.
    /// > ref: <https://bitcoin.stackexchange.com/questions/117356/what-is-sigop-signature-operation#117359>
    ///
    /// The `spent` parameter is a closure/function that looks up the output being spent by each input
    /// It takes in an [`OutPoint`] and returns a [`TxOut`]. If you can't provide this, a placeholder of
    /// `|_| None` can be used. Without access to the previous [`TxOut`], any sigops in a redeemScript (P2SH)
    /// as well as any SegWit sigops will not be counted for that input.
    fn total_sigop_cost<S>(&self, spent: S) -> usize
    where
        S: FnMut(&OutPoint) -> Option<TxOut>;

    /// Returns a reference to the input at `input_index` if it exists.
    fn tx_in(&self, input_index: usize) -> Result<&TxIn, InputsIndexError>;

    /// Returns a reference to the output at `output_index` if it exists.
    fn tx_out(&self, output_index: usize) -> Result<&TxOut, OutputsIndexError>;
}

impl TransactionExt for Transaction {
    fn ntxid(&self) -> Ntxid { self.compute_ntxid() }

    fn txid(&self) -> Txid { self.compute_txid() }

    fn wtxid(&self) -> Wtxid { self.compute_wtxid() }

    #[inline]
    fn weight(&self) -> Weight {
        // In Bitcoin Cash there is no witness discount: weight = size * 4.
        Weight::from_wu(self.total_size().to_u64() * 4)
    }

    fn base_size(&self) -> usize {
        let mut size: usize = 4; // Serialized length of a u32 for the version number.

        size += compact_size::encoded_size(self.inputs.len());
        size += self.inputs.iter().map(|input| input.base_size()).sum::<usize>();

        size += compact_size::encoded_size(self.outputs.len());
        size += self.outputs.iter().map(|output| output.size()).sum::<usize>();

        size + absolute::LockTime::SIZE
    }

    #[inline]
    fn total_size(&self) -> usize { self.base_size() }

    #[inline]
    fn vsize(&self) -> usize {
        // No overflow because it's computed from data in memory
        self.weight().to_vbytes_ceil() as usize
    }

    #[doc(alias = "is_coin_base")] // method previously had this name
    fn is_coinbase(&self) -> bool {
        self.inputs.len() == 1 && self.inputs[0].previous_output == OutPoint::COINBASE_PREVOUT
    }

    fn is_explicitly_rbf(&self) -> bool { self.inputs.iter().any(|input| input.sequence.is_rbf()) }

    fn is_absolute_timelock_satisfied(&self, height: Height, time: MedianTimePast) -> bool {
        if !self.is_lock_time_enabled() {
            return true;
        }
        self.lock_time.is_satisfied_by(height, time)
    }

    fn is_lock_time_enabled(&self) -> bool { self.inputs.iter().any(|i| i.enables_lock_time()) }

    fn script_pubkey_lens(&self) -> TxOutToScriptPubkeyLengthIter<'_> {
        TxOutToScriptPubkeyLengthIter { inner: self.outputs.iter() }
    }

    fn total_sigop_cost<S>(&self, mut spent: S) -> usize
    where
        S: FnMut(&OutPoint) -> Option<TxOut>,
    {
        let mut cost = self.count_p2pk_p2pkh_sigops().saturating_mul(4);

        // coinbase tx is correctly handled because `spent` will always returns None.
        cost.saturating_add(self.count_p2sh_sigops(&mut spent).saturating_mul(4))
    }

    #[inline]
    fn tx_in(&self, input_index: usize) -> Result<&TxIn, InputsIndexError> {
        self.inputs
            .get(input_index)
            .ok_or(IndexOutOfBoundsError { index: input_index, length: self.inputs.len() }.into())
    }

    #[inline]
    fn tx_out(&self, output_index: usize) -> Result<&TxOut, OutputsIndexError> {
        self.outputs
            .get(output_index)
            .ok_or(IndexOutOfBoundsError { index: output_index, length: self.outputs.len() }.into())
    }
}

/// Iterates over transaction outputs and for each output yields the length of the scriptPubkey.
// This exists to hardcode the type of the closure created by `map`.
pub struct TxOutToScriptPubkeyLengthIter<'a> {
    inner: core::slice::Iter<'a, TxOut>,
}

impl Iterator for TxOutToScriptPubkeyLengthIter<'_> {
    type Item = usize;

    fn next(&mut self) -> Option<usize> { self.inner.next().map(|txout| txout.script_pubkey.len()) }
}

trait TransactionExtPriv {
    /// Gets the sigop count.
    ///
    /// Counts sigops for this transaction's input scriptSigs and output scriptPubkeys i.e., doesn't
    /// count sigops in the redeemScript for p2sh (use `count_p2sh_sigops` for those).
    fn count_p2pk_p2pkh_sigops(&self) -> usize;

    /// Counts P2SH sigops.
    fn count_p2sh_sigops<S>(&self, spent: S) -> usize
    where
        S: FnMut(&OutPoint) -> Option<TxOut>;
}

impl TransactionExtPriv for Transaction {
    /// Gets the sigop count.
    fn count_p2pk_p2pkh_sigops(&self) -> usize {
        let mut count: usize = 0;
        for input in &self.inputs {
            // 0 for p2wpkh, p2wsh, and p2sh (including wrapped SegWit).
            count = count.saturating_add(input.script_sig.count_sigops_legacy());
        }
        for output in &self.outputs {
            count = count.saturating_add(output.script_pubkey.count_sigops_legacy());
        }
        count
    }

    fn count_p2sh_sigops<S>(&self, mut spent: S) -> usize
    where
        S: FnMut(&OutPoint) -> Option<TxOut>,
    {
        fn count_sigops(prevout: &TxOut, input: &TxIn) -> usize {
            let mut count: usize = 0;
            if prevout.script_pubkey.is_p2sh() {
                if let Some(redeem) = input.script_sig.last_pushdata() {
                    count = count
                        .saturating_add(RedeemScript::from_bytes(redeem.as_bytes()).count_sigops());
                }
            }
            count
        }

        let mut count: usize = 0;
        for input in &self.inputs {
            if let Some(prevout) = spent(&input.previous_output) {
                count = count.saturating_add(count_sigops(&prevout, input));
            }
        }
        count
    }

}

/// Error attempting to do an out of bounds access on the transaction inputs vector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputsIndexError(pub IndexOutOfBoundsError);

impl fmt::Display for InputsIndexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_err!(f, "invalid input index"; self.0)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for InputsIndexError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { Some(&self.0) }
}

impl From<IndexOutOfBoundsError> for InputsIndexError {
    fn from(e: IndexOutOfBoundsError) -> Self { Self(e) }
}

/// Error attempting to do an out of bounds access on the transaction outputs vector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutputsIndexError(pub IndexOutOfBoundsError);

impl fmt::Display for OutputsIndexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_err!(f, "invalid output index"; self.0)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for OutputsIndexError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { Some(&self.0) }
}

impl From<IndexOutOfBoundsError> for OutputsIndexError {
    fn from(e: IndexOutOfBoundsError) -> Self { Self(e) }
}

/// Error attempting to do an out of bounds access on a vector.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct IndexOutOfBoundsError {
    /// Attempted index access.
    pub index: usize,
    /// Length of the vector where access was attempted.
    pub length: usize,
}

impl fmt::Display for IndexOutOfBoundsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "index {} is out-of-bounds for vector with length {}", self.index, self.length)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for IndexOutOfBoundsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { None }
}

impl Encodable for Version {
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        self.to_u32().consensus_encode(w)
    }
}

impl Decodable for Version {
    fn consensus_decode<R: BufRead + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        Decodable::consensus_decode(r).map(Version::maybe_non_standard)
    }
}

crate::internal_macros::impl_consensus_encoding!(TxOut, value, script_pubkey);

impl Encodable for OutPoint {
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        let len = self.txid.consensus_encode(w)?;
        Ok(len + self.vout.consensus_encode(w)?)
    }
}
impl Decodable for OutPoint {
    fn consensus_decode<R: BufRead + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        Ok(OutPoint {
            txid: Decodable::consensus_decode(r)?,
            vout: Decodable::consensus_decode(r)?,
        })
    }
}

impl Encodable for TxIn {
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        let mut len = 0;
        len += self.previous_output.consensus_encode(w)?;
        len += self.script_sig.consensus_encode(w)?;
        len += self.sequence.consensus_encode(w)?;
        Ok(len)
    }
}
impl Decodable for TxIn {
    #[inline]
    fn consensus_decode_from_finite_reader<R: BufRead + ?Sized>(
        r: &mut R,
    ) -> Result<Self, encode::Error> {
        Ok(TxIn {
            previous_output: Decodable::consensus_decode_from_finite_reader(r)?,
            script_sig: Decodable::consensus_decode_from_finite_reader(r)?,
            sequence: Decodable::consensus_decode_from_finite_reader(r)?,
        })
    }
}

impl Encodable for Sequence {
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        self.0.consensus_encode(w)
    }
}

impl Decodable for Sequence {
    fn consensus_decode<R: BufRead + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        Decodable::consensus_decode(r).map(Sequence)
    }
}

impl Encodable for Transaction {
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        let mut len = 0;
        len += self.version.consensus_encode(w)?;
        // Bitcoin Cash uses legacy (pre-SegWit) serialization only.
        len += self.inputs.consensus_encode(w)?;
        len += self.outputs.consensus_encode(w)?;
        len += self.lock_time.consensus_encode(w)?;
        Ok(len)
    }
}

impl Decodable for Transaction {
    fn consensus_decode_from_finite_reader<R: BufRead + ?Sized>(
        r: &mut R,
    ) -> Result<Self, encode::Error> {
        // Bitcoin Cash uses legacy (pre-SegWit) serialization only.
        Ok(Transaction {
            version: Version::consensus_decode_from_finite_reader(r)?,
            inputs: Vec::<TxIn>::consensus_decode_from_finite_reader(r)?,
            outputs: Vec::<TxOut>::consensus_decode_from_finite_reader(r)?,
            lock_time: Decodable::consensus_decode_from_finite_reader(r)?,
        })
    }
}

/// Computes the value of an output accounting for the cost of spending it.
///
/// The effective value is the value of an output value minus the amount to spend it. That is, the
/// effective_value can be calculated as: value - (fee_rate * weight).
///
/// Note: the effective value of a [`Transaction`] may increase less than the effective value of
/// a [`TxOut`] when adding another [`TxOut`] to the transaction. This happens when the new
/// [`TxOut`] added causes the output length `CompactSize` to increase its encoding length.
///
/// # Parameters
///
/// * `fee_rate` - the fee rate of the transaction being created.
/// * `input_weight_prediction` - the predicted input weight.
/// * `value` - the value of the output we are spending.
pub fn effective_value(
    fee_rate: FeeRate,
    input_weight_prediction: InputWeightPrediction,
    value: Amount,
) -> SignedAmount {
    let weight = input_weight_prediction.total_weight();
    let fee = fee_rate.to_fee(weight);

    value.signed_sub(fee)
}

/// Predicts the weight of a to-be-constructed transaction.
///
/// This function computes the weight of a transaction which is not fully known. All that is needed
/// is the lengths of scripts and witness elements.
///
/// # Parameters
///
/// * `inputs` - an iterator which returns `InputWeightPrediction` for each input of the
///   to-be-constructed transaction.
/// * `output_script_lens` - an iterator which returns the length of `script_pubkey` of each output
///   of the to-be-constructed transaction.
///
/// Note that lengths of the scripts and witness elements must be non-serialized, IOW *without* the
/// length prefix. The length is computed and added inside the function for convenience.
///
/// If you have the transaction already constructed (except for signatures) with a dummy value for
/// fee output you can use the return value of [`Transaction::script_pubkey_lens`] method directly
/// as the second argument.
///
/// # Usage
///
/// When signing a transaction one doesn't know the signature before knowing the transaction fee and
/// the transaction fee is not known before knowing the transaction size which is not known before
/// knowing the signature. This apparent dependency cycle can be broken by knowing the length of the
/// signature without knowing the contents of the signature e.g., we know all Schnorr signatures
/// are 64 bytes long.
///
/// Additionally, some protocols may require calculating the amounts before knowing various parts
/// of the transaction (assuming their length is known).
///
/// # Notes on integer overflow
///
/// Overflows are intentionally not checked because one of the following holds:
///
/// * The transaction is valid (obeys the block size limit) and the code feeds correct values to
///   this function - no overflow can happen.
/// * The transaction will be so large it doesn't fit in the memory - overflow will happen but
///   then the transaction will fail to construct and even if one serialized it on disk directly
///   it'd be invalid anyway so overflow doesn't matter.
/// * The values fed into this function are inconsistent with the actual lengths the transaction
///   will have - the code is already broken and checking overflows doesn't help. Unfortunately
///   this probably cannot be avoided.
pub fn predict_weight<I, O>(inputs: I, output_script_lens: O) -> Weight
where
    I: IntoIterator<Item = InputWeightPrediction>,
    O: IntoIterator<Item = usize>,
{
    let (input_count, input_weight) =
        inputs.into_iter().fold((0, 0), |(count, weight), prediction| {
            (count + 1, weight + prediction.total_weight().to_wu() as usize)
        });

    let (output_count, output_scripts_size) =
        output_script_lens.into_iter().fold((0, 0), |(count, scripts_size), script_len| {
            (count + 1, scripts_size + script_len + compact_size::encoded_size(script_len))
        });

    predict_weight_internal(
        input_count,
        input_weight,
        0, // No witness inputs in BCH
        output_count,
        output_scripts_size,
    )
}

const fn predict_weight_internal(
    input_count: usize,
    input_weight: usize,
    _inputs_with_witnesses: usize,
    output_count: usize,
    output_scripts_size: usize,
) -> Weight {
    // The value field of a TxOut is 8 bytes.
    let output_size = 8 * output_count + output_scripts_size;
    let non_input_size = 4 // version
        + compact_size::encoded_size_const(input_count as u64) // Can't use ToU64 in const context.
        + compact_size::encoded_size_const(output_count as u64)
        + output_size
        + 4; // locktime
    // Bitcoin Cash has no witness discount: weight = size * 4 always.
    let weight = non_input_size * 4 + input_weight;
    Weight::from_wu(weight as u64)
}

/// Predicts the weight of a to-be-constructed transaction in const context.
///
/// This is a `const` version of [`predict_weight`] which only allows slices due to current Rust
/// limitations around `const fn`. Because of these limitations it may be less efficient than
/// `predict_weight` and thus is intended to be only used in `const` context.
///
/// Please see the documentation of `predict_weight` to learn more about this function.
pub const fn predict_weight_from_slices(
    inputs: &[InputWeightPrediction],
    output_script_lens: &[usize],
) -> Weight {
    let mut input_weight = 0;

    // for loops not supported in const fn
    let mut i = 0;
    while i < inputs.len() {
        let prediction = inputs[i];
        input_weight += prediction.total_weight().to_wu() as usize;
        i += 1;
    }

    let mut output_scripts_size = 0;

    i = 0;
    while i < output_script_lens.len() {
        let script_len = output_script_lens[i];
        output_scripts_size += script_len + compact_size::encoded_size_const(script_len as u64);
        i += 1;
    }

    predict_weight_internal(
        inputs.len(),
        input_weight,
        0, // No witness inputs in BCH
        output_script_lens.len(),
        output_scripts_size,
    )
}

/// Weight prediction of an individual input.
///
/// This helper type collects information about an input to be used in [`predict_weight`] function.
/// It can only be created using the [`new`](InputWeightPrediction::new) function or using other
/// associated constants/methods.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct InputWeightPrediction {
    script_size: u32,
    witness_size: u32,
}

impl InputWeightPrediction {
    /// Input weight prediction corresponding to spending of a P2PKH output with the largest possible
    /// DER-encoded signature, and a compressed public key.
    ///
    /// If the input in your transaction uses P2PKH with a compressed key, you can use this instead of
    /// [`InputWeightPrediction::new`].
    ///
    /// This is useful when you **do not** use [signature grinding] and want to ensure you are not
    /// under-paying. See [`ground_p2pkh_compressed`](Self::ground_p2pkh_compressed) if you do use
    /// signature grinding.
    ///
    /// [signature grinding]: https://bitcoin.stackexchange.com/questions/111660/what-is-signature-grinding
    pub const P2PKH_COMPRESSED_MAX: Self = InputWeightPrediction::from_slice(107, &[]);

    /// Input weight prediction corresponding to spending of a P2PKH output with the largest possible
    /// DER-encoded signature, and an uncompressed public key.
    ///
    /// If the input in your transaction uses P2PKH with an uncompressed key, you can use this instead of
    /// [`InputWeightPrediction::new`].
    pub const P2PKH_UNCOMPRESSED_MAX: Self = InputWeightPrediction::from_slice(139, &[]);

    const fn saturate_to_u32(x: usize) -> u32 {
        if x > u32::MAX as usize {
            u32::MAX
        } else {
            x as u32 //cast ok, condition prevents larger than u32::MAX.
        }
    }

    const fn encoded_size(value: usize) -> u32 {
        match value {
            0..=0xFC => 1,
            0xFD..=0xFFFF => 3,
            0x10000..=0xFFFFFFFF => 5,
            _ => 9,
        }
    }

    /// Input weight prediction corresponding to spending of a P2PKH output using [signature
    /// grinding], and a compressed public key.
    ///
    /// If the input in your transaction uses compressed P2PKH and you use signature grinding you
    /// can use this instead of [`InputWeightPrediction::new`]. See
    /// [`P2PKH_COMPRESSED_MAX`](Self::P2PKH_COMPRESSED_MAX) if you don't use signature grinding.
    ///
    /// Note: `bytes_to_grind` is usually `1` because of exponential cost of higher values.
    ///
    /// # Panics
    ///
    /// The function panics in const context and debug builds if `bytes_to_grind` is higher than 62.
    ///
    /// [signature grinding]: https://bitcoin.stackexchange.com/questions/111660/what-is-signature-grinding
    pub const fn ground_p2pkh_compressed(bytes_to_grind: usize) -> Self {
        // Written to trigger const/debug panic for unreasonably high values.
        let der_signature_size = 10 + (62 - bytes_to_grind);

        InputWeightPrediction::from_slice(2 + 33 + der_signature_size, &[])
    }

    /// Computes the prediction for a single input.
    pub fn new<T>(input_script_len: usize, witness_element_lengths: T) -> Self
    where
        T: IntoIterator,
        T::Item: Borrow<usize>,
    {
        let (count, total_size) = witness_element_lengths.into_iter().fold(
            (0usize, 0u32),
            |(count, total_size), elem_len| {
                let elem_len = *elem_len.borrow();
                let elem_size =
                    Self::saturate_to_u32(elem_len).saturating_add(Self::encoded_size(elem_len));
                (count + 1, total_size.saturating_add(elem_size))
            },
        );
        let witness_size = if count > 0 { total_size + Self::encoded_size(count) } else { 0 };
        let script_size =
            Self::saturate_to_u32(input_script_len) + Self::encoded_size(input_script_len);

        InputWeightPrediction { script_size, witness_size }
    }

    /// Computes the prediction for a single input in `const` context.
    ///
    /// This is a `const` version of [`new`](Self::new) which only allows slices due to current Rust
    /// limitations around `const fn`. Because of these limitations it may be less efficient than
    /// `new` and thus is intended to be only used in `const` context.
    pub const fn from_slice(input_script_len: usize, witness_element_lengths: &[usize]) -> Self {
        let mut i = 0;
        let mut total_size: u32 = 0;
        // for loops not supported in const fn
        while i < witness_element_lengths.len() {
            let elem_len = witness_element_lengths[i];
            let elem_size =
                Self::saturate_to_u32(elem_len).saturating_add(Self::encoded_size(elem_len));
            total_size = total_size.saturating_add(elem_size);
            i += 1;
        }
        let witness_size = if !witness_element_lengths.is_empty() {
            total_size.saturating_add(Self::encoded_size(witness_element_lengths.len()))
        } else {
            0
        };
        let script_size = Self::saturate_to_u32(input_script_len)
            .saturating_add(Self::encoded_size(input_script_len));

        InputWeightPrediction { script_size, witness_size }
    }

    /// Computes the **signature weight** added to a transaction by an input with this weight prediction,
    /// not counting the prevout (txid, index), sequence, potential witness flag bytes or the witness count.
    ///
    /// This function's internal arithmetic saturates at u32::MAX, so the return value of this
    /// function may be inaccurate for extremely large witness predictions.
    #[deprecated(since = "TBD", note = "use `InputWeightPrediction::witness_weight()` instead")]
    pub const fn weight(&self) -> Weight { Self::witness_weight(self) }

    /// Computes the signature, prevout (txid, index), and sequence weights of this weight
    /// prediction.
    ///
    /// This function's internal arithmetic saturates at u32::MAX, so the return value of this
    /// function may be inaccurate for extremely large witness predictions.
    ///
    /// See also [`InputWeightPrediction::witness_weight`]
    pub const fn total_weight(&self) -> Weight {
        // `impl const Trait` is currently unavailable: rust/issues/67792
        // Convert to u64s because we can't use `Add` in const context.
        let weight = TX_IN_BASE_WEIGHT.to_wu() + Self::witness_weight(self).to_wu();
        Weight::from_wu(weight)
    }

    /// Computes the **signature weight** added to a transaction by an input with this weight prediction,
    /// not counting the prevout (txid, index), sequence, potential witness flag bytes or the witness count.
    ///
    /// This function's internal arithmetic saturates at u32::MAX, so the return value of this
    /// function may be inaccurate for extremely large witness predictions.
    ///
    /// See also [`InputWeightPrediction::total_weight`]
    pub const fn witness_weight(&self) -> Weight {
        let wu = self.script_size * 4 + self.witness_size;
        let wu = const_casts::u32_to_u64(wu);
        Weight::from_wu(wu)
    }
}

internals::transparent_newtype! {
    /// A wrapper type for the coinbase transaction of a block.
    ///
    /// This type exists to distinguish coinbase transactions from regular ones at the type level.
    #[derive(Clone, PartialEq, Eq, Debug, Hash)]
    pub struct Coinbase(Transaction);

    impl Coinbase {
        /// Constructs a reference to `Coinbase` from a reference to the inner `Transaction`.
        ///
        /// This method does not validate that the transaction is actually a coinbase transaction.
        /// The caller must ensure that the transaction is indeed a valid coinbase transaction
        pub fn assume_coinbase_ref(inner: &_) -> &Self;
    }
}

impl Coinbase {
    /// Constructs a `Coinbase` wrapper assuming this transaction is a coinbase transaction.
    ///
    /// This method does not validate that the transaction is actually a coinbase transaction.
    /// The caller must ensure that this transaction is indeed a valid coinbase transaction.
    pub fn assume_coinbase(tx: Transaction) -> Self { Self(tx) }

    /// Returns the first input of this coinbase transaction.
    ///
    /// This method is infallible because a valid coinbase transaction is guaranteed
    /// to have exactly one input.
    pub fn first_input(&self) -> &TxIn { &self.0.inputs[0] }

    /// Returns a reference to the underlying transaction.
    ///
    /// Warning: The coinbase input contains dummy prevouts that should not be treated as real prevouts.
    #[doc(alias = "as_inner")]
    pub fn as_transaction(&self) -> &Transaction { &self.0 }

    /// Returns the underlying transaction.
    ///
    /// Warning: The coinbase input contains dummy prevouts that should not be treated as real prevouts.
    #[doc(alias = "into_inner")]
    pub fn into_transaction(self) -> Transaction { self.0 }

    /// Computes the [`Txid`] of this coinbase transaction.
    pub fn compute_txid(&self) -> Txid { self.0.compute_txid() }

    /// Returns the wtxid of this coinbase transaction.
    ///
    /// For coinbase transactions, this is always `Wtxid::COINBASE`.
    #[doc(alias = "compute_wtxid")]
    pub const fn wtxid(&self) -> Wtxid { Wtxid::COINBASE }
}

mod sealed {
    pub trait Sealed {}
    impl Sealed for super::Transaction {}
    impl Sealed for super::Txid {}
    impl Sealed for super::Wtxid {}
    impl Sealed for super::OutPoint {}
    impl Sealed for super::TxIn {}
    impl Sealed for super::TxOut {}
    impl Sealed for super::Version {}
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for InputWeightPrediction {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        match u.int_in_range(0..=3)? {
            0 => Ok(InputWeightPrediction::P2PKH_COMPRESSED_MAX),
            1 => Ok(InputWeightPrediction::P2PKH_UNCOMPRESSED_MAX),
            2 => {
                let input_script_len = usize::arbitrary(u)?;
                let witness_element_lengths: Vec<usize> = Vec::arbitrary(u)?;
                Ok(InputWeightPrediction::new(input_script_len, witness_element_lengths))
            }
            _ => {
                let input_script_len = usize::arbitrary(u)?;
                let witness_element_lengths: Vec<usize> = Vec::arbitrary(u)?;
                Ok(InputWeightPrediction::from_slice(input_script_len, &witness_element_lengths))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use hex::FromHex;
    use hex_lit::hex;
    use units::parse;

    use super::*;
    use crate::consensus::encode::{deserialize, serialize};
    use crate::constants::WITNESS_SCALE_FACTOR;
    use crate::script::ScriptSigBuf;
    use crate::sighash::EcdsaSighashType;

    const SOME_TX: &str = "0100000001a15d57094aa7a21a28cb20b59aab8fc7d1149a3bdbcddba9c622e4f5f6a99ece010000006c493046022100f93bb0e7d8db7bd46e40132d1f8242026e045f03a0efe71bbb8e3f475e970d790221009337cd7f1f929f00cc6ff01f03729b069a7c21b59b1736ddfee5db5946c5da8c0121033b9b137ee87d5a812d6f506efdd37f0affa7ffc310711c06c7f3e097c9447c52ffffffff0100e1f505000000001976a9140389035a9225b3839e2bbf32d826a1e222031fd888ac00000000";

    #[test]
    fn encode_to_unsized_writer() {
        let mut buf = [0u8; 1024];
        let raw_tx = hex!(SOME_TX);
        let tx: Transaction = Decodable::consensus_decode(&mut raw_tx.as_slice()).unwrap();

        let size = tx.consensus_encode(&mut &mut buf[..]).unwrap();
        assert_eq!(size, SOME_TX.len() / 2);
        assert_eq!(raw_tx, &buf[..size]);
    }

    #[test]
    fn outpoint() {
        assert_eq!("i don't care".parse::<OutPoint>(), Err(ParseOutPointError::Format));
        assert_eq!(
            "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456:1:1"
                .parse::<OutPoint>(),
            Err(ParseOutPointError::Format)
        );
        assert_eq!(
            "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456:".parse::<OutPoint>(),
            Err(ParseOutPointError::Format)
        );
        assert_eq!(
            "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456:11111111111"
                .parse::<OutPoint>(),
            Err(ParseOutPointError::TooLong)
        );
        assert_eq!(
            "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456:01"
                .parse::<OutPoint>(),
            Err(ParseOutPointError::VoutNotCanonical)
        );
        assert_eq!(
            "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456:+42"
                .parse::<OutPoint>(),
            Err(ParseOutPointError::VoutNotCanonical)
        );
        assert_eq!(
            "i don't care:1".parse::<OutPoint>(),
            Err(ParseOutPointError::Txid("i don't care".parse::<Txid>().unwrap_err()))
        );
        assert_eq!(
            "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c945X:1"
                .parse::<OutPoint>(),
            Err(ParseOutPointError::Txid(
                "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c945X"
                    .parse::<Txid>()
                    .unwrap_err()
            ))
        );
        assert_eq!(
            "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456:lol"
                .parse::<OutPoint>(),
            Err(ParseOutPointError::Vout(parse::int_from_str::<u32>("lol").unwrap_err()))
        );

        assert_eq!(
            "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456:42"
                .parse::<OutPoint>(),
            Ok(OutPoint {
                txid: "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456"
                    .parse()
                    .unwrap(),
                vout: 42,
            })
        );
        assert_eq!(
            "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456:0"
                .parse::<OutPoint>(),
            Ok(OutPoint {
                txid: "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456"
                    .parse()
                    .unwrap(),
                vout: 0,
            })
        );
    }

    #[test]
    fn txin() {
        let txin: Result<TxIn, _> = deserialize(&hex!("a15d57094aa7a21a28cb20b59aab8fc7d1149a3bdbcddba9c622e4f5f6a99ece010000006c493046022100f93bb0e7d8db7bd46e40132d1f8242026e045f03a0efe71bbb8e3f475e970d790221009337cd7f1f929f00cc6ff01f03729b069a7c21b59b1736ddfee5db5946c5da8c0121033b9b137ee87d5a812d6f506efdd37f0affa7ffc310711c06c7f3e097c9447c52ffffffff"));
        assert!(txin.is_ok());
    }

    #[test]
    fn is_coinbase() {
        use crate::constants;
        use crate::network::Network;

        let genesis = constants::genesis_block(Network::Bitcoin);
        assert!(genesis.transactions()[0].is_coinbase());
        let tx_bytes = hex!("0100000001a15d57094aa7a21a28cb20b59aab8fc7d1149a3bdbcddba9c622e4f5f6a99ece010000006c493046022100f93bb0e7d8db7bd46e40132d1f8242026e045f03a0efe71bbb8e3f475e970d790221009337cd7f1f929f00cc6ff01f03729b069a7c21b59b1736ddfee5db5946c5da8c0121033b9b137ee87d5a812d6f506efdd37f0affa7ffc310711c06c7f3e097c9447c52ffffffff0100e1f505000000001976a9140389035a9225b3839e2bbf32d826a1e222031fd888ac00000000");
        let tx: Transaction = deserialize(&tx_bytes).unwrap();
        assert!(!tx.is_coinbase());
    }

    #[test]
    fn nonsegwit_transaction() {
        let tx_bytes = hex!("0100000001a15d57094aa7a21a28cb20b59aab8fc7d1149a3bdbcddba9c622e4f5f6a99ece010000006c493046022100f93bb0e7d8db7bd46e40132d1f8242026e045f03a0efe71bbb8e3f475e970d790221009337cd7f1f929f00cc6ff01f03729b069a7c21b59b1736ddfee5db5946c5da8c0121033b9b137ee87d5a812d6f506efdd37f0affa7ffc310711c06c7f3e097c9447c52ffffffff0100e1f505000000001976a9140389035a9225b3839e2bbf32d826a1e222031fd888ac00000000");
        let tx: Result<Transaction, _> = deserialize(&tx_bytes);
        assert!(tx.is_ok());
        let realtx = tx.unwrap();
        // All these tests aren't really needed because if they fail, the hash check at the end
        // will also fail. But these will show you where the failure is so I'll leave them in.
        assert_eq!(realtx.version, Version::ONE);
        assert_eq!(realtx.inputs.len(), 1);
        // In particular this one is easy to get backward -- in bitcoin hashes are encoded
        // as little-endian 256-bit numbers rather than as data strings.
        assert_eq!(
            format!("{:x}", realtx.inputs[0].previous_output.txid),
            "ce9ea9f6f5e422c6a9dbcddb3b9a14d1c78fab9ab520cb281aa2a74a09575da1".to_string()
        );
        assert_eq!(realtx.inputs[0].previous_output.vout, 1);
        assert_eq!(realtx.outputs.len(), 1);
        assert_eq!(realtx.lock_time, absolute::LockTime::ZERO);

        assert_eq!(
            format!("{:x}", realtx.compute_txid()),
            "a6eab3c14ab5272a58a5ba91505ba1a4b6d7a3a9fcbd187b6cd99a7b6d548cb7".to_string()
        );
        assert_eq!(
            format!("{:x}", realtx.compute_wtxid()),
            "a6eab3c14ab5272a58a5ba91505ba1a4b6d7a3a9fcbd187b6cd99a7b6d548cb7".to_string()
        );
        assert_eq!(realtx.weight().to_wu() as usize, tx_bytes.len() * WITNESS_SCALE_FACTOR);
        assert_eq!(realtx.total_size(), tx_bytes.len());
        assert_eq!(realtx.vsize(), tx_bytes.len());
        assert_eq!(realtx.base_size(), tx_bytes.len());
    }

    #[test]
    fn segwit_invalid_transaction() {
        let tx_bytes = hex!("0000fd000001021921212121212121212121f8b372b0239cc1dff600000000004f4f4f4f4f4f4f4f000000000000000000000000000000333732343133380d000000000000000000000000000000ff000000000009000dff000000000000000800000000000000000d");
        let tx: Result<Transaction, _> = deserialize(&tx_bytes);
        assert!(tx.is_err());
        assert!(matches!(tx.unwrap_err(), crate::consensus::DeserializeError::Parse(_)));
    }

    // We temporarily abuse `Transaction` for testing consensus serde adapter.
    #[test]
    #[cfg(feature = "serde")]
    fn consensus_serde() {
        use crate::consensus::serde as con_serde;
        // Legacy BCH transaction (P2PKH spend)
        let json = "\"0100000001a15d57094aa7a21a28cb20b59aab8fc7d1149a3bdbcddba9c622e4f5f6a99ece010000006c493046022100f93bb0e7d8db7bd46e40132d1f8242026e045f03a0efe71bbb8e3f475e970d790221009337cd7f1f929f00cc6ff01f03729b069a7c21b59b1736ddfee5db5946c5da8c0121033b9b137ee87d5a812d6f506efdd37f0affa7ffc310711c06c7f3e097c9447c52ffffffff0100e1f505000000001976a9140389035a9225b3839e2bbf32d826a1e222031fd888ac00000000\"";
        let mut deserializer = serde_json::Deserializer::from_str(json);
        let tx =
            con_serde::With::<con_serde::Hex>::deserialize::<'_, Transaction, _>(&mut deserializer)
                .unwrap();
        let tx_bytes = Vec::from_hex(&json[1..(json.len() - 1)]).unwrap();
        let expected = deserialize::<Transaction>(&tx_bytes).unwrap();
        assert_eq!(tx, expected);
        let mut bytes = Vec::new();
        let mut serializer = serde_json::Serializer::new(&mut bytes);
        con_serde::With::<con_serde::Hex>::serialize(&tx, &mut serializer).unwrap();
        assert_eq!(bytes, json.as_bytes())
    }

    #[test]
    fn transaction_version() {
        let tx_bytes = hex!("ffffffff0100000000000000000000000000000000000000000000000000000000000000000000000000ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000");
        let tx: Result<Transaction, _> = deserialize(&tx_bytes);
        assert!(tx.is_ok());
        let realtx = tx.unwrap();
        assert_eq!(realtx.version, Version::maybe_non_standard(u32::MAX));
    }

    #[test]
    fn ntxid() {
        let tx_bytes = hex!("0100000001a15d57094aa7a21a28cb20b59aab8fc7d1149a3bdbcddba9c622e4f5f6a99ece010000006c493046022100f93bb0e7d8db7bd46e40132d1f8242026e045f03a0efe71bbb8e3f475e970d790221009337cd7f1f929f00cc6ff01f03729b069a7c21b59b1736ddfee5db5946c5da8c0121033b9b137ee87d5a812d6f506efdd37f0affa7ffc310711c06c7f3e097c9447c52ffffffff0100e1f505000000001976a9140389035a9225b3839e2bbf32d826a1e222031fd888ac00000000");
        let mut tx: Transaction = deserialize(&tx_bytes).unwrap();

        let old_ntxid = tx.compute_ntxid();
        assert_eq!(
            format!("{:x}", old_ntxid),
            "c3573dbea28ce24425c59a189391937e00d255150fa973d59d61caf3a06b601d"
        );
        // changing sigs does not affect it
        tx.inputs[0].script_sig = ScriptSigBuf::new();
        assert_eq!(old_ntxid, tx.compute_ntxid());
        // changing pks does
        tx.outputs[0].script_pubkey = ScriptPubKeyBuf::new();
        assert!(old_ntxid != tx.compute_ntxid());
    }

    #[test]
    fn txid() {
        // Legacy tx
        let tx_bytes = hex!(
            "01000000010c7196428403d8b0c88fcb3ee8d64f56f55c8973c9ab7dd106bb4f3527f5888d000000006a47\
             30440220503a696f55f2c00eee2ac5e65b17767cd88ed04866b5637d3c1d5d996a70656d02202c9aff698f\
             343abb6d176704beda63fcdec503133ea4f6a5216b7f925fa9910c0121024d89b5a13d6521388969209df2\
             7a8469bd565aff10e8d42cef931fad5121bfb8ffffffff02b825b404000000001976a914ef79e7ee9fff98\
             bcfd08473d2b76b02a48f8c69088ac0000000000000000296a273236303039343836393731373233313237\
             3633313032313332353630353838373931323132373000000000"
        );
        let tx: Transaction = deserialize(&tx_bytes).unwrap();

        assert_eq!(
            format!("{:x}", tx.compute_wtxid()),
            "971ed48a62c143bbd9c87f4bafa2ef213cfa106c6e140f111931d0be307468dd"
        );
        assert_eq!(
            format!("{:x}", tx.compute_txid()),
            "971ed48a62c143bbd9c87f4bafa2ef213cfa106c6e140f111931d0be307468dd"
        );
    }

    #[test]
    fn sighashtype_fromstr_display() {
        let sighashtypes = [
            ("SIGHASH_ALL", EcdsaSighashType::All),
            ("SIGHASH_NONE", EcdsaSighashType::None),
            ("SIGHASH_SINGLE", EcdsaSighashType::Single),
            ("SIGHASH_ALL|SIGHASH_ANYONECANPAY", EcdsaSighashType::AllPlusAnyoneCanPay),
            ("SIGHASH_NONE|SIGHASH_ANYONECANPAY", EcdsaSighashType::NonePlusAnyoneCanPay),
            ("SIGHASH_SINGLE|SIGHASH_ANYONECANPAY", EcdsaSighashType::SinglePlusAnyoneCanPay),
        ];
        for (s, sht) in sighashtypes {
            assert_eq!(sht.to_string(), s);
            assert_eq!(s.parse::<EcdsaSighashType>().unwrap(), sht);
        }
        let sht_mistakes = [
            "SIGHASH_ALL | SIGHASH_ANYONECANPAY",
            "SIGHASH_NONE |SIGHASH_ANYONECANPAY",
            "SIGHASH_SINGLE| SIGHASH_ANYONECANPAY",
            "SIGHASH_ALL SIGHASH_ANYONECANPAY",
            "SIGHASH_NONE |",
            "SIGHASH_SIGNLE",
            "sighash_none",
            "Sighash_none",
            "SigHash_None",
            "SigHash_NONE",
        ];
        for s in sht_mistakes {
            assert_eq!(
                s.parse::<EcdsaSighashType>().unwrap_err().to_string(),
                format!("unrecognized SIGHASH string '{}'", s)
            );
        }
    }

    #[test]
    fn sequence_number() {
        let seq_final = Sequence::from_consensus(0xFFFFFFFF);
        let seq_non_rbf = Sequence::from_consensus(0xFFFFFFFE);
        let block_time_lock = Sequence::from_consensus(0xFFFF);
        let unit_time_lock = Sequence::from_consensus(0x40FFFF);
        let lock_time_disabled = Sequence::from_consensus(0x80000000);

        assert!(seq_final.is_final());
        assert!(!seq_final.is_rbf());
        assert!(!seq_final.is_relative_lock_time());
        assert!(!seq_non_rbf.is_rbf());
        assert!(block_time_lock.is_relative_lock_time());
        assert!(block_time_lock.is_height_locked());
        assert!(block_time_lock.is_rbf());
        assert!(unit_time_lock.is_relative_lock_time());
        assert!(unit_time_lock.is_time_locked());
        assert!(unit_time_lock.is_rbf());
        assert!(!lock_time_disabled.is_relative_lock_time());
    }

    #[test]
    fn sequence_from_hex_lower() {
        let sequence = Sequence::from_hex("0xffffffff").unwrap();
        assert_eq!(sequence, Sequence::MAX);
    }

    #[test]
    fn sequence_from_hex_upper() {
        let sequence = Sequence::from_hex("0XFFFFFFFF").unwrap();
        assert_eq!(sequence, Sequence::MAX);
    }

    #[test]
    fn sequence_from_unprefixed_hex_lower() {
        let sequence = Sequence::from_unprefixed_hex("ffffffff").unwrap();
        assert_eq!(sequence, Sequence::MAX);
    }

    #[test]
    fn sequence_from_unprefixed_hex_upper() {
        let sequence = Sequence::from_unprefixed_hex("FFFFFFFF").unwrap();
        assert_eq!(sequence, Sequence::MAX);
    }

    #[test]
    fn sequence_from_str_hex_invalid_hex_should_err() {
        let hex = "0xzb93";
        let result = Sequence::from_hex(hex);
        assert!(result.is_err());
    }

    #[test]
    fn effective_value_happy_path() {
        let value = "1 cBTC".parse::<Amount>().unwrap();
        let fee_rate = FeeRate::from_sat_per_kwu(10);
        let prediction = InputWeightPrediction::P2PKH_COMPRESSED_MAX;
        let actual = effective_value(fee_rate, prediction, value);
        let fee = fee_rate.to_fee(prediction.total_weight());
        let expected_effective_value = (value.to_signed() - fee.to_signed()).unwrap();
        assert_eq!(actual, expected_effective_value);
    }

    #[test]
    fn effective_value_fee_rate_does_not_overflow() {
        // Should not panic with extreme fee rates.
        let _ = effective_value(FeeRate::MAX, InputWeightPrediction::P2PKH_COMPRESSED_MAX, Amount::ZERO);
    }

    #[test]
    fn txin_txout_weight() {
        // [(tx_hex, expected_weight)] - legacy transactions only (BCH has no segwit)
        let txs = [
                // three legacy inputs (P2PKH)
                "0100000003e4d7be4314204a239d8e00691128dca7927e19a7339c7948bde56f669d27d797010000006b483045022100b988a858e2982e2daaf0755b37ad46775d6132057934877a5badc91dee2f66ff022020b967c1a2f0916007662ec609987e951baafa6d4fda23faaad70715611d6a2501210254a2dccd8c8832d4677dc6f0e562eaaa5d11feb9f1de2c50a33832e7c6190796ffffffff9e22eb1b3f24c260187d716a8a6c2a7efb5af14a30a4792a6eeac3643172379c000000006a47304402207df07f0cd30dca2cf7bed7686fa78d8a37fe9c2254dfdca2befed54e06b779790220684417b8ff9f0f6b480546a9e90ecee86a625b3ea1e4ca29b080da6bd6c5f67e01210254a2dccd8c8832d4677dc6f0e562eaaa5d11feb9f1de2c50a33832e7c6190796ffffffff1123df3bfb503b59769731da103d4371bc029f57979ebce68067768b958091a1000000006a47304402207a016023c2b0c4db9a7d4f9232fcec2193c2f119a69125ad5bcedcba56dd525e02206a734b3a321286c896759ac98ebfd9d808df47f1ce1fbfbe949891cc3134294701210254a2dccd8c8832d4677dc6f0e562eaaa5d11feb9f1de2c50a33832e7c6190796ffffffff0200c2eb0b000000001976a914e5eb3e05efad136b1405f5c2f9adb14e15a35bb488ac88cfff1b000000001976a9144846db516db3130b7a3c92253599edec6bc9630b88ac00000000",
                // one legacy input (P2PKH)
                "0100000001c336895d9fa674f8b1e294fd006b1ac8266939161600e04788c515089991b50a030000006a47304402204213769e823984b31dcb7104f2c99279e74249eacd4246dabcf2575f85b365aa02200c3ee89c84344ae326b637101a92448664a8d39a009c8ad5d147c752cbe112970121028b1b44b4903c9103c07d5a23e3c7cf7aeb0ba45ddbd2cfdce469ab197381f195fdffffff040000000000000000536a4c5058325bb7b7251cf9e36cac35d691bd37431eeea426d42cbdecca4db20794f9a4030e6cb5211fabf887642bcad98c9994430facb712da8ae5e12c9ae5ff314127d33665000bb26c0067000bb0bf00322a50c300000000000017a9145ca04fdc0a6d2f4e3f67cfeb97e438bb6287725f8750c30000000000001976a91423086a767de0143523e818d4273ddfe6d9e4bbcc88acc8465003000000001976a914c95cbacc416f757c65c942f9b6b8a20038b9b12988ac00000000",
            ];

        let empty_transaction_weight = Transaction {
            version: Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            inputs: vec![],
            outputs: vec![],
        }
        .weight();

        for tx_hex in &txs {
            let tx: Transaction = deserialize(Vec::from_hex(tx_hex).unwrap().as_slice()).unwrap();
            let calculated_weight = empty_transaction_weight
                + tx.inputs.iter().fold(Weight::ZERO, |sum, i| sum + i.legacy_weight())
                + tx.outputs.iter().fold(Weight::ZERO, |sum, o| sum + o.weight());
            assert_eq!(calculated_weight, tx.weight());
        }
    }

    #[test]
    fn tx_sigop_count() {
        let tx_hexes = [
            // 0 sigops (p2pkh in, p2wpkh-script out) - legacy format, BCH compatible
            (
                "0200000001725aab4d23f76ad10bb569a68f8702ebfb8b076e015179ff9b9425234953\
                ac63000000006a47304402204cae7dc9bb68b588dd6b8afb8b881b752fd65178c25693e\
                a6d5d9a08388fd2a2022011c753d522d5c327741a6d922342c86e05c928309d7e566f68\
                8148432e887028012103f14b11cfb58b113716e0fa277ab4a32e4d3ed64c6b09b1747ef\
                7c828d5b06a94fdffffff01e5d4830100000000160014e98527b55cae861e5b9c3a6794\
                86514c012d6fce00000000",
                0,                                             // Expected (Some)
                return_none as fn(&OutPoint) -> Option<TxOut>, // spent fn
                0,                                             // Expected (None)
            ),
            // 12 sigops (1 P2SH 2-of-3 MS in (3x4), P2SH outs (0))
            (
                "010000000115fe9ec3dc964e41f5267ea26cfe505f202bf3b292627496b04bece84da9\
                b18903000000fc004730440220442827f1085364bda58c5884cee7b289934083362db6d\
                fb627dc46f6cdbf5793022078cfa524252c381f2a572f0c41486e2838ca94aa268f2384\
                d0e515744bf0e1e9014730440220160e49536bb29a49c7626744ee83150174c22fa40d5\
                8fb4cd554a907a6a7b825022045f6cf148504b334064686795f0968c689e542f475b8ef\
                5a5fa42383948226a3014c69522103e54bc61efbcb8eeff3a5ab2a92a75272f5f6820e3\
                8e3d28edb54beb06b86c0862103a553e30733d7a8df6d390d59cc136e2c9d9cf4e808f3\
                b6ab009beae68dd60822210291c5a54bb8b00b6f72b90af0ac0ecaf78fab026d8eded28\
                2ad95d4d65db268c953aeffffffff024c4f0d000000000017a9146ebf0484bd5053f727\
                c755a750aa4c815dfa112887a06b12020000000017a91410065dd50b3a7f299fef3b1c5\
                3b8216399916ab08700000000",
                12,
                return_p2sh,
                0,
            ),
            // 80 sigops (1 P2PKH in, 1 BARE MS out (20x4))
            (
                "0100000001628c1726fecd23331ae9ff2872341b82d2c03180aa64f9bceefe457448db\
                e579020000006a47304402204799581a5b34ae5adca21ef22c55dbfcee58527127c95d0\
                1413820fe7556ed970220391565b24dc47ce57fe56bf029792f821a392cdb5a3d45ed85\
                c158997e7421390121037b2fb5b602e51c493acf4bf2d2423bcf63a09b3b99dfb7bd3c8\
                d74733b5d66f5ffffffff011c0300000000000069512103a29472a1848105b2225f0eca\
                5c35ada0b0abbc3c538818a53eca177f4f4dcd9621020c8fd41b65ae6b980c072c5a9f3\
                aec9f82162c92eb4c51d914348f4390ac39122102222222222222222222222222222222\
                222222222222222222222222222222222253ae00000000",
                80,
                return_none,
                80,
            ),
        ];

        fn return_p2sh(_outpoint: &OutPoint) -> Option<TxOut> {
            Some(
                deserialize(&hex!(
                    "cc721b000000000017a91428203c10cc8f18a77412caaa83dabaf62b8fbb0f87"
                ))
                .unwrap(),
            )
        }
        fn return_none(_outpoint: &OutPoint) -> Option<TxOut> { None }

        for (hx, expected, spent_fn, expected_none) in tx_hexes.iter() {
            let tx_bytes = Vec::from_hex(hx).unwrap();
            let tx: Transaction = deserialize(&tx_bytes).unwrap();
            assert_eq!(tx.total_sigop_cost(spent_fn), *expected);
            assert_eq!(tx.total_sigop_cost(return_none), *expected_none);
        }
    }

    #[test]
    fn weight_predictions() {
        // Legacy P2PKH transaction
        let tx_raw = hex!(
            "0100000001a15d57094aa7a21a28cb20b59aab8fc7d1149a3bdbcddba9c622e4f5f6a99ece010000006c\
             493046022100f93bb0e7d8db7bd46e40132d1f8242026e045f03a0efe71bbb8e3f475e970d790221009337\
             cd7f1f929f00cc6ff01f03729b069a7c21b59b1736ddfee5db5946c5da8c0121033b9b137ee87d5a812d6f\
             506efdd37f0affa7ffc310711c06c7f3e097c9447c52ffffffff0100e1f505000000001976a9140389035a\
             9225b3839e2bbf32d826a1e222031fd888ac00000000"
        );
        let tx = Transaction::consensus_decode::<&[u8]>(&mut tx_raw.as_ref()).unwrap();
        let input_weights = vec![InputWeightPrediction::P2PKH_COMPRESSED_MAX];
        let predicted = predict_weight(input_weights, tx.script_pubkey_lens());
        let expected = tx.weight();
        assert_eq!(predicted, expected);

        assert_eq!(
            InputWeightPrediction::ground_p2pkh_compressed(0).witness_weight(),
            InputWeightPrediction::P2PKH_COMPRESSED_MAX.witness_weight()
        );
    }

    #[test]
    fn weight_prediction_const_from_slices() {
        let predict = [
            InputWeightPrediction::P2PKH_COMPRESSED_MAX,
            InputWeightPrediction::P2PKH_UNCOMPRESSED_MAX,
        ];

        let weight = predict_weight_from_slices(&predict, &[1]);
        // Verify it gives a plausible weight (non-zero)
        assert!(weight.to_wu() > 0);
    }

    #[test]
    // needless_borrows_for_generic_args incorrectly identifies &[] as a needless borrow
    #[allow(clippy::needless_borrows_for_generic_args)]
    fn weight_prediction_new() {
        let p2pkh_compressed_max = InputWeightPrediction::new(107, &[]);
        assert_eq!(p2pkh_compressed_max.script_size, 108);
        assert_eq!(p2pkh_compressed_max.witness_size, 0);
        assert_eq!(p2pkh_compressed_max.total_weight(), Weight::from_wu(592));
        assert_eq!(
            p2pkh_compressed_max.total_weight(),
            InputWeightPrediction::P2PKH_COMPRESSED_MAX.total_weight()
        );

        let p2pkh_uncompressed_max = InputWeightPrediction::new(139, &[]);
        assert_eq!(p2pkh_uncompressed_max.script_size, 140);
        assert_eq!(p2pkh_uncompressed_max.witness_size, 0);
        assert_eq!(p2pkh_uncompressed_max.total_weight(), Weight::from_wu(720));
        assert_eq!(
            p2pkh_uncompressed_max.total_weight(),
            InputWeightPrediction::P2PKH_UNCOMPRESSED_MAX.total_weight()
        );
    }

    #[test]
    fn sequence_debug_output() {
        let seq = Sequence::from_seconds_floor(1000);
        println!("{:?}", seq)
    }

    #[test]
    fn outpoint_format() {
        let outpoint = OutPoint::COINBASE_PREVOUT;

        let debug = "OutPoint { txid: 0000000000000000000000000000000000000000000000000000000000000000, vout: 4294967295 }";
        assert_eq!(debug, format!("{:?}", &outpoint));

        let display = "0000000000000000000000000000000000000000000000000000000000000000:4294967295";
        assert_eq!(display, format!("{}", &outpoint));

        let pretty_debug = "OutPoint {\n    txid: 0x0000000000000000000000000000000000000000000000000000000000000000,\n    vout: 4294967295,\n}";
        assert_eq!(pretty_debug, format!("{:#?}", &outpoint));

        let debug_txid = "0000000000000000000000000000000000000000000000000000000000000000";
        assert_eq!(debug_txid, format!("{:?}", &outpoint.txid));

        let display_txid = "0000000000000000000000000000000000000000000000000000000000000000";
        assert_eq!(display_txid, format!("{}", &outpoint.txid));

        let pretty_txid = "0x0000000000000000000000000000000000000000000000000000000000000000";
        assert_eq!(pretty_txid, format!("{:#}", &outpoint.txid));
    }

    #[test]
    fn coinbase_assume_methods() {
        use crate::constants;
        use crate::network::Network;

        let genesis = constants::genesis_block(Network::Bitcoin);
        let coinbase_tx = &genesis.transactions()[0];

        // Test that we can create a Coinbase reference using assume_coinbase_ref
        let coinbase_ref = Coinbase::assume_coinbase_ref(coinbase_tx);
        assert_eq!(coinbase_ref.compute_txid(), coinbase_tx.compute_txid());
        assert_eq!(coinbase_ref.wtxid(), Wtxid::COINBASE);

        // Test that we can create a Coinbase using assume_coinbase
        let coinbase_owned = Coinbase::assume_coinbase(coinbase_tx.clone());
        assert_eq!(coinbase_owned.compute_txid(), coinbase_tx.compute_txid());
        assert_eq!(coinbase_owned.wtxid(), Wtxid::COINBASE);
    }
}

#[cfg(bench)]
mod benches {
    use io::sink;
    use test::{black_box, Bencher};

    use super::*;
    use crate::consensus::{encode, Encodable};

    const SOME_TX: &str = "0100000001a15d57094aa7a21a28cb20b59aab8fc7d1149a3bdbcddba9c622e4f5f6a99ece010000006c493046022100f93bb0e7d8db7bd46e40132d1f8242026e045f03a0efe71bbb8e3f475e970d790221009337cd7f1f929f00cc6ff01f03729b069a7c21b59b1736ddfee5db5946c5da8c0121033b9b137ee87d5a812d6f506efdd37f0affa7ffc310711c06c7f3e097c9447c52ffffffff0100e1f505000000001976a9140389035a9225b3839e2bbf32d826a1e222031fd888ac00000000";

    #[bench]
    pub fn bench_transaction_size(bh: &mut Bencher) {
        let mut tx: Transaction = encode::deserialize_hex(SOME_TX).unwrap();

        bh.iter(|| {
            black_box(black_box(&mut tx).total_size());
        });
    }

    #[bench]
    pub fn bench_transaction_serialize(bh: &mut Bencher) {
        let tx: Transaction = encode::deserialize_hex(SOME_TX).unwrap();
        let mut data = Vec::with_capacity(SOME_TX.len());

        bh.iter(|| {
            let result = tx.consensus_encode(&mut data);
            black_box(&result);
            data.clear();
        });
    }

    #[bench]
    pub fn bench_transaction_serialize_logic(bh: &mut Bencher) {
        let tx: Transaction = encode::deserialize_hex(SOME_TX).unwrap();

        bh.iter(|| {
            let size = tx.consensus_encode(&mut sink());
            black_box(&size);
        });
    }

    #[bench]
    pub fn bench_transaction_deserialize(bh: &mut Bencher) {
        // hex_lit does not work in bench code for some reason. Perhaps criterion fixes this.
        let raw_tx = <Vec<u8> as hex::FromHex>::from_hex(SOME_TX).unwrap();

        bh.iter(|| {
            let tx: Transaction = encode::deserialize(&raw_tx).unwrap();
            black_box(&tx);
        });
    }

    #[bench]
    pub fn bench_transaction_deserialize_hex(bh: &mut Bencher) {
        bh.iter(|| {
            let tx: Transaction = encode::deserialize_hex(SOME_TX).unwrap();
            black_box(&tx);
        });
    }
}
