use bitcoin::ext::*;
use bitcoin::{consensus, ecdsa, sighash, ScriptPubKey, Transaction};
use hex_lit::hex;

// These are real blockchain transaction examples of computing sighash for:
// - P2MS 2of3 (bare multisig)
// - P2SH 2of2 multisig
//
// run with: cargo run --example sighash

/// Computes sighash for a legacy multisig transaction input that spends either a p2sh or a p2ms output.
///
/// # Parameters
///
/// * `raw_tx` - the spending tx hex
/// * `inp_idx` - the spending tx input index
/// * `script_pubkey_bytes_opt` - the Option with scriptPubKey bytes. If None, it's p2sh case,
///   i.e., reftx output's scriptPubKey.type is "scripthash". In this case scriptPubkey is
///   extracted from the spending transaction's scriptSig. If Some(), it's p2ms case, i.e., reftx
///   output's scriptPubKey.type is "multisig", and the scriptPubkey is supplied from the
///   referenced output.
fn compute_sighash_legacy(raw_tx: &[u8], inp_idx: usize, script_pubkey_bytes_opt: Option<&[u8]>) {
    let tx: Transaction = consensus::deserialize(raw_tx).unwrap();
    let inp = &tx.inputs[inp_idx];
    let script_sig = &inp.script_sig;
    println!("scriptSig is: {script_sig}");
    let cache = sighash::SighashCache::new(&tx);
    // In the P2SH case we get scriptPubKey from scriptSig of the spending input.
    // The scriptSig that corresponds to an M of N multisig should be:
    // PUSHBYTES_0 PUSHBYTES_K0 <sig0><sighashflag0> ... PUSHBYTES_Km <sigM><sighashflagM> PUSHBYTES_X <scriptPubKey>
    // Here we assume that we have an M of N multisig scriptPubKey.
    let mut instructions: Vec<_> = script_sig.instructions().collect();
    let script_pubkey_p2sh;
    let script_pubkey_bytes = match script_pubkey_bytes_opt {
        // In the P2MS case, the scriptPubKey is in the referenced output, passed into this function.
        Some(bytes) => bytes,
        // In the P2SH case, the scriptPubKey is the last scriptSig PushBytes instruction.
        None => {
            script_pubkey_p2sh = instructions.pop().unwrap().unwrap();
            script_pubkey_p2sh.push_bytes().unwrap().as_bytes()
        }
    };
    let script_code = ScriptPubKey::from_bytes(script_pubkey_bytes);
    let pushbytes_0 = instructions.remove(0).unwrap();
    assert!(
        pushbytes_0.push_bytes().unwrap().as_bytes().is_empty(),
        "first in ScriptSig must be PUSHBYTES_0 got {pushbytes_0:?}"
    );

    // All other scriptSig instructions must be signatures.
    for instr in instructions {
        let sig = ecdsa::Signature::from_slice(instr.unwrap().push_bytes().unwrap().as_bytes())
            .expect("failed to parse sig");
        let sighash = cache
            .legacy_signature_hash(inp_idx, script_code, sig.sighash_type.to_u32())
            .expect("failed to compute sighash");
        println!("Legacy sighash: {:x} (sighash flag {})", sighash, sig.sighash_type);
    }
}

fn main() {
    sighash_p2ms_multisig_2x3();
    sighash_p2sh_multisig_2x2();
}

fn sighash_p2sh_multisig_2x2() {
    // Spending transaction:
    // bitcoin-cli getrawtransaction 214646c4b563cd8c788754ec94468ab71602f5ed07d5e976a2b0e41a413bcc0e  3
    // After decoding ScriptSig from input 0, its last ASM element is the scriptpubkey:
    // bitcoin-cli decodescript 5221032d7306898e980c66aefdfb6b377eaf71597c449bf9ce741a3380c5646354f6de2103e8c742e1f283ef810c1cd0c8875e5c2998a05fc5b23c30160d3d33add7af565752ae
    // Its ASM is 2 of 2 multisig:
    // 2 032d7306898e980c66aefdfb6b377eaf71597c449bf9ce741a3380c5646354f6de
    //   03e8c742e1f283ef810c1cd0c8875e5c2998a05fc5b23c30160d3d33add7af5657
    // 2 OP_CHECKMULTISIG
    let raw_tx = hex!("0100000001d611ad58b2f5bc0db7d15dfde4f497d6482d1b4a1e8c462ef077d4d32b3dae7901000000da0047304402203b17b4f64fa7299e8a85a688bda3cb1394b80262598bbdffd71dab1d7f266098022019cc20dc20eae417374609cb9ca22b28261511150ed69d39664b9d3b1bcb3d1201483045022100cfff9c400abb4ce5f247bd1c582cf54ec841719b0d39550b714c3c793fb4347b02201427a961a7f32aba4eeb1b71b080ea8712705e77323b747c03c8f5dbdda1025a01475221032d7306898e980c66aefdfb6b377eaf71597c449bf9ce741a3380c5646354f6de2103e8c742e1f283ef810c1cd0c8875e5c2998a05fc5b23c30160d3d33add7af565752aeffffffff020ed000000000000016001477800cff52bd58133b895622fd1220d9e2b47a79cd0902000000000017a914da55145ca5c56ba01f1b0b98d896425aa4b0f4468700000000");
    let inp_idx = 0;

    println!("\nsighash_p2sh_multisig_2x2:");
    compute_sighash_legacy(&raw_tx, inp_idx, None);
}

fn sighash_p2ms_multisig_2x3() {
    // Spending tx:
    // bitcoin-cli getrawtransaction 949591ad468cef5c41656c0a502d9500671ee421fadb590fbc6373000039b693  3
    // Inp 0 scriptSig has 2 sigs.
    let raw_tx = hex!("010000000110a5fee9786a9d2d72c25525e52dd70cbd9035d5152fac83b62d3aa7e2301d58000000009300483045022100af204ef91b8dba5884df50f87219ccef22014c21dd05aa44470d4ed800b7f6e40220428fe058684db1bb2bfb6061bff67048592c574effc217f0d150daedcf36787601483045022100e8547aa2c2a2761a5a28806d3ae0d1bbf0aeff782f9081dfea67b86cacb321340220771a166929469c34959daf726a2ac0c253f9aff391e58a3c7cb46d8b7e0fdc4801ffffffff0180a21900000000001976a914971802edf585cdbc4e57017d6e5142515c1e502888ac00000000");
    // Original transaction:
    // bitcoin-cli getrawtransaction 581d30e2a73a2db683ac2f15d53590bd0cd72de52555c2722d9d6a78e9fea510  3
    // Out 0 scriptPubKey.type "multisig" has 3 uncompressed pubkeys.
    let reftx_script_pubkey_bytes = hex!("524104d81fd577272bbe73308c93009eec5dc9fc319fc1ee2e7066e17220a5d47a18314578be2faea34b9f1f8ca078f8621acd4bc22897b03daa422b9bf56646b342a24104ec3afff0b2b66e8152e9018fe3be3fc92b30bf886b3487a525997d00fd9da2d012dce5d5275854adc3106572a5d1e12d4211b228429f5a7b2f7ba92eb0475bb14104b49b496684b02855bc32f5daefa2e2e406db4418f3b86bca5195600951c7d918cdbe5e6d3736ec2abf2dd7610995c3086976b2c0c7b4e459d10b34a316d5a5e753ae");
    let inp_idx = 0;

    println!("\nsighash_p2ms_multisig_2x3:");
    compute_sighash_legacy(&raw_tx, inp_idx, Some(&reftx_script_pubkey_bytes));
}
