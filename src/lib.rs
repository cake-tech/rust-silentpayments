//! A rust implementation of BIP352: Silent Payments.  This library
//! can be used to add silent payment support to wallets.
//!
//! This library is split up in two parts: sending and receiving.
//! Either of these can be implemented independently using
//! the `sending` or `receiving` features.
//!
//! ## Examples
//!
//! Will be added soon.
//! In the meantime, have a look at the [test vectors from the BIP](https://github.com/cygnet3/rust-silentpayments/blob/master/tests/vector_tests.rs)
//! to see how to do a simple implementation.
//!
//! Alternatively, have a look at [Donation wallet](https://github.com/cygnet3/sp-backend/tree/master),
//! which is a WIP 'silent payments native' wallet.
#![allow(dead_code, non_snake_case)]
mod common;
mod error;

#[cfg(feature = "receiving")]
pub mod receiving;
#[cfg(feature = "sending")]
pub mod sending;
pub mod utils;

use core::slice;

pub use bitcoin_hashes;
use receiving::Receiver;
pub use secp256k1;
use secp256k1::{PublicKey, Scalar, SecretKey, XOnlyPublicKey};

pub use crate::error::Error;
use crate::{receiving::Label, utils::receiving::calculate_shared_secret};

pub type Result<T> = std::result::Result<T, Error>;

#[repr(C)]
pub struct OutputData {
    pubkey_bytes: *const u8,
    amount: u64,
}

#[repr(C)]
pub struct ReceiverData {
    b_scan_bytes: *const u8,
    B_spend_bytes: *const u8,
    is_testnet: bool,
    labels: *const u32,
    labels_len: u64,
}

#[repr(C)]
pub struct ParamData {
    outputs_data: *const *const OutputData,
    outputs_data_len: u64,
    tweak_bytes: *const u8,
    receiver_data: *const ReceiverData,
}

#[repr(C)]
pub struct BytesVec {
    data: *mut u8,
    len: usize,
}

#[no_mangle]
pub extern "C" fn api_scan_outputs(data: *const ParamData) -> BytesVec {
    let data = unsafe { &*data };

    let outputs_slice =
        unsafe { slice::from_raw_parts(data.outputs_data, data.outputs_data_len as usize) };

    let outputs_to_check: Vec<XOnlyPublicKey> = outputs_slice
        .iter()
        .filter_map(|&vout_data_ptr| {
            let vout_data = unsafe { &*vout_data_ptr };
            let pubkey_slice = unsafe { slice::from_raw_parts(vout_data.pubkey_bytes, 32) };
            XOnlyPublicKey::from_slice(pubkey_slice).ok()
        })
        .collect();


    let b_scan = unsafe {
        SecretKey::from_slice(slice::from_raw_parts(
            data.receiver_data.as_ref().unwrap().b_scan_bytes,
            32,
        ))
        .unwrap()
    };
    let B_spend = unsafe {
        PublicKey::from_slice(slice::from_raw_parts(
            data.receiver_data.as_ref().unwrap().B_spend_bytes,
            33,
        ))
        .unwrap()
    };
    let is_testnet = unsafe { data.receiver_data.as_ref().unwrap().is_testnet };
    let change_label = Label::new(b_scan, 0);

    let secp = secp256k1::Secp256k1::new();
    let mut sp_receiver = Receiver::new(
        0,
        b_scan.public_key(&secp),
        B_spend,
        change_label,
        is_testnet,
    )
    .unwrap();

    let labels = unsafe { slice::from_raw_parts(data.receiver_data.as_ref().unwrap().labels, data.receiver_data.as_ref().unwrap().labels_len as usize) };
    for label_int in labels {
        let label = Label::new(b_scan, *label_int);
        sp_receiver.add_label(label).unwrap();
    }
    
    let tweak_data =
        unsafe { PublicKey::from_slice(slice::from_raw_parts(data.tweak_bytes, 33)).unwrap() };
    let shared_secret = calculate_shared_secret(tweak_data, b_scan).unwrap();
    let scanned_outputs_received = sp_receiver
        .scan_transaction(&shared_secret, outputs_to_check)
        .unwrap();
    println!("scanned_outputs_received: {:?}", scanned_outputs_received);
    let key_tweaks: Vec<Scalar> = scanned_outputs_received
        .into_iter()
        .flat_map(|(_, map)| {
            let mut ret: Vec<Scalar> = vec![];
            for l in map.into_values() {
                ret.push(l);
            }
            ret
        })
        .collect();

    let bytes: Vec<u8> = key_tweaks.iter().flat_map(|scalar| scalar.to_be_bytes()).collect();
    // let bytes = [bytes.clone(), bytes.clone()].concat();
    // Capture the length of the bytes vector before forgetting it
    let bytes_len = bytes.len();

    // Obtain a raw pointer to the vector's buffer
    let bytes_ptr = bytes.as_ptr() as *mut u8;

    // Now, we can forget the bytes vector to prevent Rust from automatically
    // deallocating its buffer when the vector goes out of scope.
    std::mem::forget(bytes);

    // Construct your BytesVec struct using the raw pointer and the length
    // captured before the forget
    BytesVec {
        data: bytes_ptr,
        len: bytes_len,
    }
}

#[no_mangle]
pub extern "C" fn free_bytes_vec(bytes_vec: *mut u8, len: usize) {
    unsafe {
        // if !bytes_vec.is_null() {
        //     let bv = Box::from_raw(bytes_vec);
        //     let data_vec = Vec::from_raw_parts(bv, len, len);
        //     drop(data_vec); // This frees the memory allocated for the bytes
        //     drop(bv); // This frees the BytesVec memory itself
        // }

        if !bytes_vec.is_null() {
            let _ = Vec::from_raw_parts(bytes_vec, len, len);
        }
    }
}
