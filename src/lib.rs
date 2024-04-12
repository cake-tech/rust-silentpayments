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
use std::{collections::HashMap, ffi::CString};

pub use bitcoin_hashes;
use bitcoin_hashes::hex::DisplayHex;
use receiving::Receiver;
pub use secp256k1;
use secp256k1::{PublicKey, SecretKey, XOnlyPublicKey};

pub use crate::error::Error;
use crate::{receiving::Label, utils::receiving::calculate_shared_secret};

use std::os::raw::c_char;

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

#[no_mangle]
pub extern "C" fn api_scan_outputs(data: *const ParamData) -> *mut i8 {
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

    let labels = unsafe {
        slice::from_raw_parts(
            data.receiver_data.as_ref().unwrap().labels,
            data.receiver_data.as_ref().unwrap().labels_len as usize,
        )
    };
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

    let mut outputs: HashMap<String, HashMap<String, String>> = HashMap::new();

    for (label, output) in scanned_outputs_received {
        let mut output_map = HashMap::new();
        for (x_only_pubkey, tweak) in output {
            output_map.insert(
                x_only_pubkey.to_string(),
                tweak.to_be_bytes().as_hex().to_string(),
            );
        }

        let result_label = if let Some(label) = label {
            label.as_string()
        } else {
            "None".to_string()
        };
        outputs.insert(result_label, output_map);
    }

    let serialized = serde_json::to_string(&outputs).unwrap();

    let c_str = CString::new(serialized).unwrap();
    let ptr = c_str.into_raw();

    ptr
}

#[no_mangle]
pub extern "C" fn free_pointer(ptr: *mut c_char) {
    unsafe {
        if !ptr.is_null() {
            drop(CString::from_raw(ptr));
        }
    }
}
