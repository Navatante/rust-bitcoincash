// SPDX-License-Identifier: CC0-1.0

//! Bitcoin Merkle tree functions.

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};
use hashes::sha256d;

hashes::hash_newtype! {
    /// A hash of the Merkle tree branch or root for transactions.
    pub struct TxMerkleNode(sha256d::Hash);
}

#[cfg(feature = "hex")]
hashes::impl_hex_for_newtype!(TxMerkleNode);
#[cfg(not(feature = "hex"))]
hashes::impl_debug_only_for_newtype!(TxMerkleNode);
#[cfg(feature = "serde")]
hashes::impl_serde_for_newtype!(TxMerkleNode);

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for TxMerkleNode {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(TxMerkleNode::from_byte_array(u.arbitrary()?))
    }
}
