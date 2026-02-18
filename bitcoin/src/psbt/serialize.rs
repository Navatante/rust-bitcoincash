// SPDX-License-Identifier: CC0-1.0

//! PSBT serialization.
//!
//! Traits to serialize PSBT values to and from raw bytes
//! according to the BIP-0174 specification.

use hashes::{hash160, ripemd160, sha256, sha256d};
use internals::compact_size;
#[allow(unused)] // MSRV polyfill
use internals::slice::SliceExt;

use super::map::{Input, Map, Output, PsbtSighashType};
use crate::bip32::{ChildNumber, Fingerprint, KeySource};
use crate::consensus::encode::{self, deserialize_partial, serialize, Decodable, Encodable};
use crate::crypto::key::PublicKey;
use crate::crypto::ecdsa;
use crate::io::Write;
use crate::prelude::{DisplayHex, String, Vec};
use crate::psbt::{Error, Psbt};
use crate::script::ScriptBuf;
use crate::transaction::{Transaction, TxOut};

/// A trait for serializing a value as raw data for insertion into PSBT
/// key-value maps.
pub(crate) trait Serialize {
    /// Serialize a value as raw data.
    fn serialize(&self) -> Vec<u8>;
}

/// A trait for deserializing a value from raw data in PSBT key-value maps.
pub(crate) trait Deserialize: Sized {
    /// Deserialize a value from raw data.
    fn deserialize(bytes: &[u8]) -> Result<Self, Error>;
}

impl Psbt {
    /// Serialize a value as bytes in hex.
    pub fn serialize_hex(&self) -> String { self.serialize().to_lower_hex_string() }

    /// Serialize as raw binary data
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::new();
        self.serialize_to_writer(&mut buf).expect("Writing to Vec can't fail");
        buf
    }

    /// Serialize the PSBT into a writer.
    pub fn serialize_to_writer(&self, w: &mut impl Write) -> io::Result<usize> {
        let mut written_len = 0;

        fn write_all(w: &mut impl Write, data: &[u8]) -> io::Result<usize> {
            w.write_all(data).map(|_| data.len())
        }

        // magic
        written_len += write_all(w, b"psbt")?;
        // separator
        written_len += write_all(w, &[0xff])?;

        written_len += write_all(w, &self.serialize_map())?;

        for i in &self.inputs {
            written_len += write_all(w, &i.serialize_map())?;
        }

        for i in &self.outputs {
            written_len += write_all(w, &i.serialize_map())?;
        }

        Ok(written_len)
    }

    /// Deserialize a value from raw binary data.
    pub fn deserialize(mut bytes: &[u8]) -> Result<Self, Error> {
        Self::deserialize_from_reader(&mut bytes)
    }

    /// Deserialize a value from raw binary data read from a `BufRead` object.
    pub fn deserialize_from_reader<R: io::BufRead>(r: &mut R) -> Result<Self, Error> {
        const MAGIC_BYTES: &[u8] = b"psbt";

        let magic: [u8; 4] = Decodable::consensus_decode(r)?;
        if magic != MAGIC_BYTES {
            return Err(Error::InvalidMagic);
        }

        const PSBT_SERPARATOR: u8 = 0xff_u8;
        let separator: u8 = Decodable::consensus_decode(r)?;
        if separator != PSBT_SERPARATOR {
            return Err(Error::InvalidSeparator);
        }

        let mut global = Psbt::decode_global(r)?;
        global.unsigned_tx_checks()?;

        let inputs: Vec<Input> = {
            let inputs_len: usize = (global.unsigned_tx.inputs).len();

            let mut inputs: Vec<Input> = Vec::with_capacity(inputs_len);

            for i in 0..inputs_len {
                let input = Input::decode(r)?;
                if let Some(ref tx) = input.non_witness_utxo {
                    let input_outpoint = global.unsigned_tx.inputs[i].previous_output;
                    let txid = tx.compute_txid();
                    if txid != input_outpoint.txid {
                        return Err(Error::IncorrectNonWitnessUtxo {
                            index: i,
                            input_outpoint,
                            non_witness_utxo_txid: txid,
                        });
                    }
                }
                inputs.push(input);
            }

            inputs
        };

        let outputs: Vec<Output> = {
            let outputs_len: usize = (global.unsigned_tx.outputs).len();

            let mut outputs: Vec<Output> = Vec::with_capacity(outputs_len);

            for _ in 0..outputs_len {
                outputs.push(Output::decode(r)?);
            }

            outputs
        };

        global.inputs = inputs;
        global.outputs = outputs;
        Ok(global)
    }
}
impl_psbt_de_serialize!(Transaction);
impl_psbt_de_serialize!(TxOut);
impl_psbt_hash_de_serialize!(ripemd160::Hash);
impl_psbt_hash_de_serialize!(sha256::Hash);
impl_psbt_hash_de_serialize!(hash160::Hash);
impl_psbt_hash_de_serialize!(sha256d::Hash);

impl<T> Serialize for ScriptBuf<T> {
    fn serialize(&self) -> Vec<u8> { self.to_vec() }
}

impl<T> Deserialize for ScriptBuf<T> {
    fn deserialize(bytes: &[u8]) -> Result<Self, Error> { Ok(Self::from(bytes.to_vec())) }
}

impl Serialize for PublicKey {
    fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.write_into(&mut buf).expect("vecs don't error");
        buf
    }
}

impl Deserialize for PublicKey {
    fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        PublicKey::from_slice(bytes).map_err(Error::InvalidPublicKey)
    }
}

impl Serialize for secp256k1::PublicKey {
    fn serialize(&self) -> Vec<u8> { self.serialize().to_vec() }
}

impl Deserialize for secp256k1::PublicKey {
    fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        secp256k1::PublicKey::from_slice(bytes).map_err(Error::InvalidSecp256k1PublicKey)
    }
}

impl Serialize for Vec<secp256k1::PublicKey> {
    fn serialize(&self) -> Vec<u8> {
        let mut result: Vec<u8> =
            Vec::with_capacity(secp256k1::constants::PUBLIC_KEY_SIZE * self.len());

        for pubkey in self.iter() {
            result.extend(Serialize::serialize(pubkey));
        }

        result
    }
}

impl Deserialize for Vec<secp256k1::PublicKey> {
    fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        bytes
            .chunks(secp256k1::constants::PUBLIC_KEY_SIZE)
            .map(secp256k1::PublicKey::deserialize)
            .collect()
    }
}

impl Serialize for ecdsa::Signature {
    fn serialize(&self) -> Vec<u8> { self.to_vec() }
}

impl Deserialize for ecdsa::Signature {
    fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        // NB: Since BIP-0174 says "the signature as would be pushed to the stack from
        // a scriptSig or witness" we should ideally use a consensus deserialization and do
        // not error on a non-standard values. However,
        //
        // 1) the current implementation of from_u32_consensus(`flag`) does not preserve
        // the sighash byte `flag` mapping all unknown values to EcdsaSighashType::All or
        // EcdsaSighashType::AllPlusAnyOneCanPay. Therefore, break the invariant
        // EcdsaSig::from_slice(&sl[..]).to_vec = sl.
        //
        // 2) This would cause to have invalid signatures because the sighash message
        // also has a field sighash_u32 (See BIP-0141). For example, when signing with non-standard
        // 0x05, the sighash message would have the last field as 0x05u32 while, the verification
        // would use check the signature assuming sighash_u32 as `0x01`.
        ecdsa::Signature::from_slice(bytes).map_err(|e| match e {
            ecdsa::DecodeError::EmptySignature => Error::InvalidEcdsaSignature(e),
            ecdsa::DecodeError::SighashType(err) => Error::NonStandardSighashType(err.0),
            ecdsa::DecodeError::Secp256k1(..) => Error::InvalidEcdsaSignature(e),
        })
    }
}

impl Serialize for KeySource {
    fn serialize(&self) -> Vec<u8> {
        let mut rv: Vec<u8> = Vec::with_capacity(key_source_len(self));

        rv.append(&mut self.0.to_byte_array().to_vec());

        for cnum in &self.1 {
            rv.append(&mut serialize(&u32::from(*cnum)))
        }

        rv
    }
}

impl Deserialize for KeySource {
    fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        let (fingerprint, mut d) =
            bytes.split_first_chunk::<4>().ok_or(io::Error::from(io::ErrorKind::UnexpectedEof))?;

        let fprint: Fingerprint = fingerprint.into();
        let mut dpath: Vec<ChildNumber> = Default::default();

        while !d.is_empty() {
            match u32::consensus_decode(&mut d) {
                Ok(index) => dpath.push(index.into()),
                Err(e) => return Err(e.into()),
            }
        }

        Ok((fprint, dpath.into()))
    }
}

// partial sigs
impl Serialize for Vec<u8> {
    fn serialize(&self) -> Vec<u8> { self.clone() }
}

impl Deserialize for Vec<u8> {
    fn deserialize(bytes: &[u8]) -> Result<Self, Error> { Ok(bytes.to_vec()) }
}

impl Serialize for PsbtSighashType {
    fn serialize(&self) -> Vec<u8> { serialize(&self.to_u32()) }
}

impl Deserialize for PsbtSighashType {
    fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        let raw: u32 = encode::deserialize(bytes)?;
        Ok(PsbtSighashType { inner: raw })
    }
}

// Helper function to compute key source len
fn key_source_len(key_source: &KeySource) -> usize { 4 + 4 * (key_source.1).as_ref().len() }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn can_deserialize_non_standard_psbt_sighash_type() {
        let non_standard_sighash = [222u8, 0u8, 0u8, 0u8]; // 32 byte value.
        let sighash = PsbtSighashType::deserialize(&non_standard_sighash);
        assert!(sighash.is_ok())
    }

    #[test]
    #[should_panic(expected = "InvalidMagic")]
    fn invalid_vector_1() {
        let hex_psbt = b"0200000001268171371edff285e937adeea4b37b78000c0566cbb3ad64641713ca42171bf6000000006a473044022070b2245123e6bf474d60c5b50c043d4c691a5d2435f09a34a7662a9dc251790a022001329ca9dacf280bdf30740ec0390422422c81cb45839457aeb76fc12edd95b3012102657d118d3357b8e0f4c2cd46db7b39f6d9c38d9a70abcb9b2de5dc8dbfe4ce31feffffff02d3dff505000000001976a914d0c59903c5bac2868760e90fd521a4665aa7652088ac00e1f5050000000017a9143545e6e33b832c47050f24d3eeb93c9c03948bc787b32e1300";
        Psbt::deserialize(hex_psbt).unwrap();
    }
}
