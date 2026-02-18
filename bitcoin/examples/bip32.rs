use std::{env, process};

use bitcoin::address::Address;
use bitcoin::bip32::{ChildNumber, DerivationPath, Xpriv, Xpub};
use bitcoin::hex::FromHex;
use bitcoin::secp256k1::ffi::types::AlignedType;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::{NetworkKind, PublicKey};

fn main() {
    // This example derives root xprv from a 32-byte seed,
    // derives the child xprv with path m/44h/145h/0h (BIP44, BCH coin type 145),
    // prints out corresponding xpub,
    // calculates and prints out the first receiving P2PKH address.
    // Run this example with cargo and seed(hex-encoded) argument:
    // cargo run --example bip32 7934c09359b234e076b9fa5a1abfd38e3dc2a9939745b7cc3c22a48d831d14bd

    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("not enough arguments. usage: {} <hex-encoded 32-byte seed>", &args[0]);
        process::exit(1);
    }

    let seed_hex = &args[1];
    println!("Seed: {seed_hex}");
    println!("Using mainnet network");

    let seed = Vec::from_hex(seed_hex).unwrap();

    // we need secp256k1 context for key derivation
    let mut buf: Vec<AlignedType> = Vec::new();
    buf.resize(Secp256k1::preallocate_size(), AlignedType::zeroed());
    let secp = Secp256k1::preallocated_new(buf.as_mut_slice()).unwrap();

    // calculate root key from seed
    let root = Xpriv::new_master(NetworkKind::Main, &seed);
    println!("Root key: {root}");

    // derive child xpub using BIP44 path for Bitcoin Cash (coin type 145)
    let path = "44h/145h/0h".parse::<DerivationPath>().unwrap();
    let child = root.derive_xpriv(&secp, &path).expect("only deriving three steps");
    println!("Child at {path}: {child}");
    let xpub = Xpub::from_xpriv(&secp, &child);
    println!("Public key at {path}: {xpub}");

    // generate first receiving address at m/0/0
    // manually creating indexes this time
    let zero = ChildNumber::ZERO_NORMAL;
    let public_key = PublicKey::new(xpub.derive_xpub(&secp, [zero, zero]).unwrap().public_key);
    let address = Address::p2pkh(public_key, NetworkKind::Main);
    println!("First receiving address: {address}");
}
