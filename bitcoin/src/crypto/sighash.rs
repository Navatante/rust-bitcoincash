// SPDX-License-Identifier: CC0-1.0

//! Signature hash implementation (used in transaction signing).
//!
//! Efficient implementation of the legacy ECDSA signature hash algorithm for Bitcoin Cash (BCH).
//! BCH uses legacy ECDSA sighash only — no SegWit v0, no Taproot.
//!
//! Computing signature hashes is required to sign a transaction and this module is designed to
//! handle its complexity efficiently. Computing these hashes is as simple as creating
//! [`SighashCache`] and calling its methods.

use core::convert::Infallible;
use core::{fmt, str};

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};
use hashes::{hash_newtype, sha256d};
use internals::write_err;
use io::Write;

use crate::consensus::Encodable;
use crate::prelude::{Borrow, String, ToOwned};
use crate::script::{ScriptExt as _, ScriptHashableTag};
use crate::transaction::TransactionExt as _;
use crate::{transaction, Amount, ScriptPubKey, Sequence, Transaction, TxOut};

/// Used for signature hash for invalid use of SIGHASH_SINGLE.
#[rustfmt::skip]
pub(crate) const UINT256_ONE: [u8; 32] = [
    1, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0
];

macro_rules! impl_message_from_hash {
    ($ty:ident) => {
        impl From<$ty> for secp256k1::Message {
            fn from(hash: $ty) -> secp256k1::Message {
                secp256k1::Message::from_digest(hash.to_byte_array())
            }
        }
    };
}

hash_newtype! {
    /// Hash of a transaction according to the legacy signature algorithm.
    #[hash_newtype(forward)]
    pub struct LegacySighash(sha256d::Hash);
}

hashes::impl_hex_for_newtype!(LegacySighash);
#[cfg(feature = "serde")]
hashes::impl_serde_for_newtype!(LegacySighash);

impl_message_from_hash!(LegacySighash);

// Implement private engine/from_engine methods for use within this module;
// but outside of it, it should not be possible to construct these hash
// types from arbitrary data (except by casting via to/from_byte_array).
impl LegacySighash {
    fn engine() -> sha256d::HashEngine { sha256d::Hash::engine() }
    fn from_engine(e: sha256d::HashEngine) -> Self { Self(sha256d::Hash::from_engine(e)) }
}

/// Calculates legacy signature hash message for Bitcoin Cash inputs.
#[derive(Debug)]
pub struct SighashCache<T: Borrow<Transaction>> {
    /// Access to transaction required for transaction introspection. Moreover, type
    /// `T: Borrow<Transaction>` allows us to use borrowed and mutable borrowed types.
    tx: T,
}

/// Hashtype of an input's signature, encoded in the last byte of the signature.
///
/// Fixed values so they can be cast as integer types for encoding.
#[derive(PartialEq, Eq, Debug, Copy, Clone, Hash)]
pub enum EcdsaSighashType {
    /// 0x1: Sign all outputs.
    All = 0x01,
    /// 0x2: Sign no outputs --- anyone can choose the destination.
    None = 0x02,
    /// 0x3: Sign the output whose index matches this input's index. If none exists,
    /// sign the hash `0000000000000000000000000000000000000000000000000000000000000001`.
    /// (This rule is probably an unintentional C++ism, but it's consensus so we have
    /// to follow it.)
    Single = 0x03,
    /// 0x81: Sign all outputs but only this input.
    AllPlusAnyoneCanPay = 0x81,
    /// 0x82: Sign no outputs and only this input.
    NonePlusAnyoneCanPay = 0x82,
    /// 0x83: Sign one output and only this input (see `Single` for what "one output" means).
    SinglePlusAnyoneCanPay = 0x83,
}
#[cfg(feature = "serde")]
internals::serde_string_impl!(EcdsaSighashType, "a EcdsaSighashType data");

impl fmt::Display for EcdsaSighashType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use EcdsaSighashType::*;

        let s = match self {
            All => "SIGHASH_ALL",
            None => "SIGHASH_NONE",
            Single => "SIGHASH_SINGLE",
            AllPlusAnyoneCanPay => "SIGHASH_ALL|SIGHASH_ANYONECANPAY",
            NonePlusAnyoneCanPay => "SIGHASH_NONE|SIGHASH_ANYONECANPAY",
            SinglePlusAnyoneCanPay => "SIGHASH_SINGLE|SIGHASH_ANYONECANPAY",
        };
        f.write_str(s)
    }
}

impl str::FromStr for EcdsaSighashType {
    type Err = SighashTypeParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        use EcdsaSighashType::*;

        match s {
            "SIGHASH_ALL" => Ok(All),
            "SIGHASH_NONE" => Ok(None),
            "SIGHASH_SINGLE" => Ok(Single),
            "SIGHASH_ALL|SIGHASH_ANYONECANPAY" => Ok(AllPlusAnyoneCanPay),
            "SIGHASH_NONE|SIGHASH_ANYONECANPAY" => Ok(NonePlusAnyoneCanPay),
            "SIGHASH_SINGLE|SIGHASH_ANYONECANPAY" => Ok(SinglePlusAnyoneCanPay),
            _ => Err(SighashTypeParseError { unrecognized: s.to_owned() }),
        }
    }
}

impl EcdsaSighashType {
    /// Splits the sighash flag into the "real" sighash flag and the ANYONECANPAY boolean.
    pub(crate) fn split_anyonecanpay_flag(self) -> (EcdsaSighashType, bool) {
        use EcdsaSighashType::*;

        match self {
            All => (All, false),
            None => (None, false),
            Single => (Single, false),
            AllPlusAnyoneCanPay => (All, true),
            NonePlusAnyoneCanPay => (None, true),
            SinglePlusAnyoneCanPay => (Single, true),
        }
    }

    /// Checks if the sighash type is [`Self::Single`] or [`Self::SinglePlusAnyoneCanPay`].
    ///
    /// This matches Bitcoin Core's behavior where SIGHASH_SINGLE bug check is based on the base
    /// type (after masking with 0x1f), regardless of the ANYONECANPAY flag.
    ///
    /// See: <https://github.com/bitcoin/bitcoin/blob/e486597/src/script/interpreter.cpp#L1618-L1619>
    pub fn is_single(&self) -> bool { matches!(self, Self::Single | Self::SinglePlusAnyoneCanPay) }

    /// Constructs a new [`EcdsaSighashType`] from a raw `u32`.
    ///
    /// **Note**: this replicates consensus behaviour, for current standardness rules correctness
    /// you probably want [`Self::from_standard`].
    ///
    /// This might cause unexpected behavior because it does not roundtrip. That is,
    /// `EcdsaSighashType::from_consensus(n) as u32 != n` for non-standard values of `n`. While
    /// verifying signatures, the user should retain the `n` and use it compute the signature hash
    /// message.
    pub fn from_consensus(n: u32) -> EcdsaSighashType {
        use EcdsaSighashType::*;

        // In Bitcoin Core, the SignatureHash function will mask the (int32) value with
        // 0x1f to (apparently) deactivate ACP when checking for SINGLE and NONE bits.
        // We however want to be matching also against on ACP-masked ALL, SINGLE, and NONE.
        // So here we re-activate ACP.
        let mask = 0x1f | 0x80;
        match n & mask {
            // "real" sighashes
            0x01 => All,
            0x02 => None,
            0x03 => Single,
            0x81 => AllPlusAnyoneCanPay,
            0x82 => NonePlusAnyoneCanPay,
            0x83 => SinglePlusAnyoneCanPay,
            // catchalls
            x if x & 0x80 == 0x80 => AllPlusAnyoneCanPay,
            _ => All,
        }
    }

    /// Constructs a new [`EcdsaSighashType`] from a raw `u32`.
    ///
    /// # Errors
    ///
    /// If `n` is a non-standard sighash value.
    pub fn from_standard(n: u32) -> Result<EcdsaSighashType, NonStandardSighashTypeError> {
        use EcdsaSighashType::*;

        match n {
            // Standard sighashes, see https://github.com/bitcoin/bitcoin/blob/b805dbb0b9c90dadef0424e5b3bf86ac308e103e/src/script/interpreter.cpp#L189-L198
            0x01 => Ok(All),
            0x02 => Ok(None),
            0x03 => Ok(Single),
            0x81 => Ok(AllPlusAnyoneCanPay),
            0x82 => Ok(NonePlusAnyoneCanPay),
            0x83 => Ok(SinglePlusAnyoneCanPay),
            non_standard => Err(NonStandardSighashTypeError(non_standard)),
        }
    }

    /// Converts [`EcdsaSighashType`] to a `u32` sighash flag.
    ///
    /// The returned value is guaranteed to be a valid according to standardness rules.
    pub fn to_u32(self) -> u32 { self as u32 }
}

/// Integer is not a consensus valid sighash type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidSighashTypeError(pub u32);

impl fmt::Display for InvalidSighashTypeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "invalid sighash type {}", self.0)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for InvalidSighashTypeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { None }
}

/// This type is consensus valid but an input including it would prevent the transaction from
/// being relayed on today's Bitcoin network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NonStandardSighashTypeError(pub u32);

impl fmt::Display for NonStandardSighashTypeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "non-standard sighash type {}", self.0)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for NonStandardSighashTypeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { None }
}

/// Error returned for failure during parsing one of the sighash types.
///
/// This is currently returned for unrecognized sighash strings.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SighashTypeParseError {
    /// The unrecognized string we attempted to parse.
    pub unrecognized: String,
}

impl fmt::Display for SighashTypeParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "unrecognized SIGHASH string '{}'", self.unrecognized)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for SighashTypeParseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { None }
}

impl<R: Borrow<Transaction>> SighashCache<R> {
    /// Constructs a new `SighashCache` from an unsigned transaction.
    ///
    /// For the generated sighashes to be valid, no fields in the transaction may change
    /// except for script_sig.
    pub fn new(tx: R) -> Self { SighashCache { tx } }

    /// Returns the reference to the cached transaction.
    pub fn transaction(&self) -> &Transaction { self.tx.borrow() }

    /// Destroys the cache and recovers the stored transaction.
    pub fn into_transaction(self) -> R { self.tx }

    /// Encodes the legacy signing data from which a signature hash for a given input index with a
    /// given sighash flag can be computed.
    ///
    /// To actually produce a scriptSig, this hash needs to be run through an ECDSA signer, the
    /// [`EcdsaSighashType`] appended to the resulting sig, and a script written around this, but
    /// this is the general (and hard) part.
    ///
    /// The `sighash_type` supports an arbitrary `u32` value, instead of just [`EcdsaSighashType`],
    /// because internally 4 bytes are being hashed, even though only the lowest byte is appended to
    /// signature in a transaction.
    ///
    /// # Warning
    ///
    /// - Does NOT attempt to support OP_CODESEPARATOR. In general this would require evaluating
    ///   `script_pubkey` to determine which separators get evaluated and which don't, which we don't
    ///   have the information to determine.
    /// - Does NOT handle the sighash single bug (see "Return type" section)
    ///
    /// # Returns
    ///
    /// This function can't handle the SIGHASH_SINGLE bug internally, so it returns [`EncodeSigningDataResult`]
    /// that must be handled by the caller (see [`EncodeSigningDataResult::is_sighash_single_bug`]).
    pub fn legacy_encode_signing_data_to<W: Write + ?Sized, U: Into<u32>, T: ScriptHashableTag>(
        &self,
        writer: &mut W,
        input_index: usize,
        script_pubkey: &crate::script::Script<T>,
        sighash_type: U,
    ) -> EncodeSigningDataResult<SigningDataError<transaction::InputsIndexError>> {
        // Validate input_index.
        if let Err(e) = self.tx.borrow().tx_in(input_index) {
            return EncodeSigningDataResult::WriteResult(Err(SigningDataError::Sighash(e)));
        }
        let sighash_type: u32 = sighash_type.into();

        if is_invalid_use_of_sighash_single(
            sighash_type,
            input_index,
            self.tx.borrow().outputs.len(),
        ) {
            // We cannot correctly handle the SIGHASH_SINGLE bug here because usage of this function
            // will result in the data written to the writer being hashed, however the correct
            // handling of the SIGHASH_SINGLE bug is to return the 'one array' - either implement
            // this behaviour manually or use `signature_hash()`.
            return EncodeSigningDataResult::SighashSingleBug;
        }

        fn encode_signing_data_to_inner<W: Write + ?Sized, T: ScriptHashableTag>(
            self_: &Transaction,
            writer: &mut W,
            input_index: usize,
            script_pubkey: &crate::script::Script<T>,
            sighash_type: u32,
        ) -> Result<(), io::Error> {
            use crate::consensus::encode::WriteExt;

            let (sighash, anyone_can_pay) =
                EcdsaSighashType::from_consensus(sighash_type).split_anyonecanpay_flag();

            self_.version.consensus_encode(writer)?;
            // Add all inputs necessary..
            if anyone_can_pay {
                writer.emit_compact_size(1u8)?;
                self_.inputs[input_index].previous_output.consensus_encode(writer)?;
                script_pubkey.consensus_encode(writer)?;
                self_.inputs[input_index].sequence.consensus_encode(writer)?;
            } else {
                writer.emit_compact_size(self_.inputs.len())?;
                for (n, input) in self_.inputs.iter().enumerate() {
                    input.previous_output.consensus_encode(writer)?;
                    if n == input_index {
                        script_pubkey.consensus_encode(writer)?;
                    } else {
                        ScriptPubKey::new().consensus_encode(writer)?;
                    }
                    if n != input_index
                        && (sighash == EcdsaSighashType::Single
                            || sighash == EcdsaSighashType::None)
                    {
                        Sequence::ZERO.consensus_encode(writer)?;
                    } else {
                        input.sequence.consensus_encode(writer)?;
                    }
                }
            }
            // ..then all outputs
            match sighash {
                EcdsaSighashType::All => {
                    self_.outputs.consensus_encode(writer)?;
                }
                EcdsaSighashType::Single => {
                    // sign all outputs up to and including this one, but erase
                    // all of them except for this one
                    let count = input_index.min(self_.outputs.len() - 1);
                    writer.emit_compact_size(count + 1)?;
                    for _ in 0..count {
                        // consensus encoding of the "NULL txout" - max amount, empty script_pubkey
                        writer
                            .write_all(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00])?;
                    }
                    self_.outputs[count].consensus_encode(writer)?;
                }
                EcdsaSighashType::None => {
                    writer.emit_compact_size(0u8)?;
                }
                _ => unreachable!(),
            };
            self_.lock_time.consensus_encode(writer)?;
            sighash_type.to_le_bytes().consensus_encode(writer)?;
            Ok(())
        }

        EncodeSigningDataResult::WriteResult(
            encode_signing_data_to_inner(
                self.tx.borrow(),
                writer,
                input_index,
                script_pubkey,
                sighash_type,
            )
            .map_err(Into::into),
        )
    }

    /// Computes a legacy signature hash for a given input index with a given sighash flag.
    ///
    /// To actually produce a scriptSig, this hash needs to be run through an ECDSA signer, the
    /// [`EcdsaSighashType`] appended to the resulting sig, and a script written around this, but
    /// this is the general (and hard) part.
    ///
    /// The `sighash_type` supports an arbitrary `u32` value, instead of just [`EcdsaSighashType`],
    /// because internally 4 bytes are being hashed, even though only the lowest byte is appended to
    /// signature in a transaction.
    ///
    /// This function correctly handles the sighash single bug by returning the 'one array'. The
    /// sighash single bug becomes exploitable when one tries to sign a transaction with
    /// `SIGHASH_SINGLE` and there is not a corresponding output with the same index as the input.
    ///
    /// # Warning
    ///
    /// Does NOT attempt to support OP_CODESEPARATOR. In general this would require evaluating
    /// `script_pubkey` to determine which separators get evaluated and which don't, which we don't
    /// have the information to determine.
    pub fn legacy_signature_hash<T: ScriptHashableTag>(
        &self,
        input_index: usize,
        script_pubkey: &crate::script::Script<T>,
        sighash_type: u32,
    ) -> Result<LegacySighash, transaction::InputsIndexError> {
        let mut engine = LegacySighash::engine();
        match self
            .legacy_encode_signing_data_to(&mut engine, input_index, script_pubkey, sighash_type)
            .is_sighash_single_bug()
        {
            Ok(true) => Ok(LegacySighash::from_byte_array(UINT256_ONE)),
            Ok(false) => Ok(LegacySighash::from_engine(engine)),
            Err(e) => Err(e.unwrap_sighash()),
        }
    }

}

fn is_invalid_use_of_sighash_single(sighash: u32, input_index: usize, outputs_len: usize) -> bool {
    let ty = EcdsaSighashType::from_consensus(sighash);
    ty.is_single() && input_index >= outputs_len
}

/// Result of [`SighashCache::legacy_encode_signing_data_to`].
///
/// This type forces the caller to handle SIGHASH_SINGLE bug case.
///
/// This corner case can't be expressed using standard `Result`,
/// in a way that is both convenient and not-prone to accidental
/// mistakes (like calling `.expect("writer never fails")`).
#[must_use]
pub enum EncodeSigningDataResult<E> {
    /// Input data is an instance of `SIGHASH_SINGLE` bug
    SighashSingleBug,
    /// Operation performed normally.
    WriteResult(Result<(), E>),
}

impl<E> EncodeSigningDataResult<E> {
    /// Checks for SIGHASH_SINGLE bug returning error if the writer failed.
    ///
    /// This method is provided for easy and correct handling of the result because
    /// SIGHASH_SINGLE bug is a special case that must not be ignored nor cause panicking.
    /// Since the data is usually written directly into a hasher which never fails,
    /// the recommended pattern to handle this is:
    ///
    /// ```rust
    /// # use bitcoin::consensus::deserialize;
    /// # use bitcoin::hashes::{sha256d, hex::FromHex};
    /// # use bitcoin::sighash::SighashCache;
    /// # use bitcoin::Transaction;
    /// # let mut writer = sha256d::Hash::engine();
    /// # let input_index = 0;
    /// # let script_pubkey = bitcoin::ScriptPubKeyBuf::new();
    /// # let sighash_u32 = 0u32;
    /// # const SOME_TX: &'static str = "0100000001a15d57094aa7a21a28cb20b59aab8fc7d1149a3bdbcddba9c622e4f5f6a99ece010000006c493046022100f93bb0e7d8db7bd46e40132d1f8242026e045f03a0efe71bbb8e3f475e970d790221009337cd7f1f929f00cc6ff01f03729b069a7c21b59b1736ddfee5db5946c5da8c0121033b9b137ee87d5a812d6f506efdd37f0affa7ffc310711c06c7f3e097c9447c52ffffffff0100e1f505000000001976a9140389035a9225b3839e2bbf32d826a1e222031fd888ac00000000";
    /// # let raw_tx = Vec::from_hex(SOME_TX).unwrap();
    /// # let tx: Transaction = deserialize(&raw_tx).unwrap();
    /// let cache = SighashCache::new(&tx);
    /// if cache.legacy_encode_signing_data_to(&mut writer, input_index, &script_pubkey, sighash_u32)
    ///         .is_sighash_single_bug()
    ///         .expect("writer can't fail") {
    ///     // use a hash value of "1", instead of computing the actual hash due to SIGHASH_SINGLE bug
    /// } else {
    ///     // use the hash from `writer`
    /// }
    /// ```
    #[allow(clippy::wrong_self_convention)] // Consume self so we can take the error.
    pub fn is_sighash_single_bug(self) -> Result<bool, E> {
        match self {
            EncodeSigningDataResult::SighashSingleBug => Ok(true),
            EncodeSigningDataResult::WriteResult(Ok(())) => Ok(false),
            EncodeSigningDataResult::WriteResult(Err(e)) => Err(e),
        }
    }

    /// Maps a `Result<T, E>` to `Result<T, F>` by applying a function to a
    /// contained [`Err`] value, leaving an [`Ok`] value untouched.
    ///
    /// Like [`Result::map_err`].
    pub fn map_err<E2, F>(self, f: F) -> EncodeSigningDataResult<E2>
    where
        F: FnOnce(E) -> E2,
    {
        match self {
            EncodeSigningDataResult::SighashSingleBug => EncodeSigningDataResult::SighashSingleBug,
            EncodeSigningDataResult::WriteResult(Err(e)) =>
                EncodeSigningDataResult::WriteResult(Err(f(e))),
            EncodeSigningDataResult::WriteResult(Ok(o)) =>
                EncodeSigningDataResult::WriteResult(Ok(o)),
        }
    }
}

/// Error returned when writing signing data fails.
#[derive(Debug)]
pub enum SigningDataError<E> {
    /// Can happen only when using `*_encode_signing_*` methods with custom writers, engines
    /// like those used in `*_signature_hash` methods do not error.
    Io(io::Error),
    /// An argument to the called sighash function was invalid.
    Sighash(E),
}

impl<E> From<Infallible> for SigningDataError<E> {
    fn from(never: Infallible) -> Self { match never {} }
}

impl<E> SigningDataError<E> {
    /// Returns the sighash variant, panicking if it's I/O.
    ///
    /// This is used when encoding to hash engine when we know that I/O doesn't fail.
    fn unwrap_sighash(self) -> E {
        match self {
            Self::Sighash(error) => error,
            Self::Io(error) => panic!("hash engine error {}", error),
        }
    }

    fn sighash<E2: Into<E>>(error: E2) -> Self { Self::Sighash(error.into()) }
}

// We cannot simultaneously impl `From<E>`. it was determined that this alternative requires less
// manual `map_err` calls.
impl<E> From<io::Error> for SigningDataError<E> {
    fn from(value: io::Error) -> Self { Self::Io(value) }
}

impl<E: fmt::Display> fmt::Display for SigningDataError<E> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Io(error) => write_err!(f, "failed to write sighash data"; error),
            Self::Sighash(error) => write_err!(f, "failed to compute sighash data"; error),
        }
    }
}

#[cfg(feature = "std")]
impl<E: std::error::Error + 'static> std::error::Error for SigningDataError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            SigningDataError::Io(error) => Some(error),
            SigningDataError::Sighash(error) => Some(error),
        }
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for EcdsaSighashType {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let choice = u.int_in_range(0..=5)?;
        match choice {
            0 => Ok(EcdsaSighashType::All),
            1 => Ok(EcdsaSighashType::None),
            2 => Ok(EcdsaSighashType::Single),
            3 => Ok(EcdsaSighashType::AllPlusAnyoneCanPay),
            4 => Ok(EcdsaSighashType::NonePlusAnyoneCanPay),
            _ => Ok(EcdsaSighashType::SinglePlusAnyoneCanPay),
        }
    }
}

#[cfg(test)]
mod tests {
    use hex::FromHex;

    use super::*;
    use crate::consensus::deserialize;
    use crate::locktime::absolute;
    use crate::script::{ScriptPubKey, ScriptPubKeyBuf};
    use crate::TxIn;

    extern crate serde_json;

    const DUMMY_TXOUT: TxOut = TxOut { value: Amount::MIN, script_pubkey: ScriptPubKeyBuf::new() };

    #[test]
    fn sighash_single_bug() {
        // We need a tx with more inputs than outputs.
        let tx = Transaction {
            version: transaction::Version::ONE,
            lock_time: absolute::LockTime::ZERO,
            inputs: vec![TxIn::EMPTY_COINBASE, TxIn::EMPTY_COINBASE],
            outputs: vec![DUMMY_TXOUT],
        };
        let script = ScriptPubKeyBuf::new();
        let cache = SighashCache::new(&tx);

        let sighash_single = 3;
        let got = cache.legacy_signature_hash(1, &script, sighash_single).expect("sighash");
        let want = LegacySighash::from_byte_array(UINT256_ONE);
        assert_eq!(got, want);

        // https://github.com/rust-bitcoin/rust-bitcoin/issues/4112
        let sighash_single = 131;
        let got = cache.legacy_signature_hash(1, &script, sighash_single).expect("sighash");
        let want = LegacySighash::from_byte_array(UINT256_ONE);
        assert_eq!(got, want);
    }

    #[test]
    #[cfg(feature = "serde")]
    fn legacy_sighash() {
        use serde_json::Value;

        use crate::sighash::SighashCache;

        fn run_test_sighash(
            tx: &str,
            script: &str,
            input_index: usize,
            hash_type: i64,
            expected_result: &str,
        ) {
            let tx: Transaction = deserialize(&Vec::from_hex(tx).unwrap()[..]).unwrap();
            let script = ScriptPubKeyBuf::from(Vec::from_hex(script).unwrap());
            let mut raw_expected = Vec::from_hex(expected_result).unwrap();
            raw_expected.reverse();
            let bytes = <[u8; 32]>::try_from(&raw_expected[..]).unwrap();
            let want = LegacySighash::from_byte_array(bytes);

            let cache = SighashCache::new(&tx);
            let got = cache.legacy_signature_hash(input_index, &script, hash_type as u32).unwrap();

            assert_eq!(got, want);
        }

        // These test vectors were stolen from libbtc, which is Copyright 2014 Jonas Schnelli MIT
        // They were transformed by replacing {...} with run_test_sighash(...), then the ones containing
        // OP_CODESEPARATOR in their pubkeys were removed
        let data = include_str!("../../tests/data/legacy_sighash.json");

        let testdata = serde_json::from_str::<Value>(data).unwrap().as_array().unwrap().clone();
        for t in testdata.iter().skip(1) {
            let tx = t.get(0).unwrap().as_str().unwrap();
            let script = t.get(1).unwrap().as_str().unwrap_or("");
            let input_index = t.get(2).unwrap().as_u64().unwrap();
            let hash_type = t.get(3).unwrap().as_i64().unwrap();
            let expected_sighash = t.get(4).unwrap().as_str().unwrap();
            run_test_sighash(tx, script, input_index as usize, hash_type, expected_sighash);
        }
    }

}
