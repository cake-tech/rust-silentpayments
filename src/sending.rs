use bech32::FromBase32;

use secp256k1::{Parity, PublicKey, Scalar, Secp256k1, SecretKey};
use std::{collections::HashMap, str::FromStr};

use sha2::Digest;

use crate::{hash_outpoints, input::SendingDataGiven, ser_uint32, sha256};

fn get_a_sum_secret_keys(input: &Vec<(String, bool)>) -> SecretKey {
    let secp = Secp256k1::new();

    let mut negated_keys: Vec<SecretKey> = vec![];

    for (keystr, is_xonly) in input {
        let key = SecretKey::from_str(&keystr).unwrap();
        let (_, parity) = key.x_only_public_key(&secp);

        if *is_xonly && parity == Parity::Odd {
            negated_keys.push(key.negate());
        } else {
            negated_keys.push(key);
        }
    }

    let (head, tail) = negated_keys.split_first().unwrap();

    let result: SecretKey = tail
        .iter()
        .fold(*head, |acc, &item| acc.add_tweak(&item.into()).unwrap());

    result
}

fn decode_silent_payment_address(addr: &str) -> (PublicKey, PublicKey) {
    let (_hrp, data, _variant) = bech32::decode(&addr).unwrap();

    let data = Vec::<u8>::from_base32(&data[1..]).unwrap();

    let B_scan = PublicKey::from_slice(&data[..33]).unwrap();
    let B_spend = PublicKey::from_slice(&data[33..]).unwrap();

    (B_scan, B_spend)
}

pub fn create_outputs(given: &SendingDataGiven) -> Vec<HashMap<String, f32>> {
    let secp = Secp256k1::new();
    // let G =

    let outpoints: &Vec<(String, u32)> = &given.outpoints;
    let outpoints_hash = hash_outpoints(outpoints);

    let input_priv_keys = &given.input_priv_keys;
    let a_sum = get_a_sum_secret_keys(input_priv_keys);

    let recipients = &given.recipients;

    let mut silent_payment_groups: HashMap<PublicKey, Vec<(PublicKey, f32)>> = HashMap::new();
    for (payment_address, amount) in recipients {
        let (B_scan, B_m) = decode_silent_payment_address(&payment_address);

        if silent_payment_groups.contains_key(&B_scan) {
            silent_payment_groups
                .get_mut(&B_scan)
                .unwrap()
                .push((B_m, *amount));
        } else {
            silent_payment_groups.insert(B_scan, vec![(B_m, *amount)]);
        }
    }

    let mut result: Vec<HashMap<String, f32>> = vec![];
    for (B_scan, B_m_values) in silent_payment_groups.into_iter() {
        let mut n = 0;

        //calculate shared secret
        let intermediate = B_scan.mul_tweak(&secp, &a_sum.into()).unwrap();
        let scalar = Scalar::from_be_bytes(outpoints_hash).unwrap();
        let ecdh_shared_secret = intermediate.mul_tweak(&secp, &scalar).unwrap().serialize();

        for (B_m, amount) in B_m_values {
            let mut bytes: Vec<u8> = Vec::new();
            bytes.extend_from_slice(&ecdh_shared_secret);
            bytes.extend_from_slice(&ser_uint32(n));

            let t_n = sha256(&bytes);
            // eprintln!("t_n = {:?}", hex::encode(t_n));

            let G: PublicKey = SecretKey::from_slice(&Scalar::ONE.to_be_bytes())
                .unwrap()
                .public_key(&secp);
            let res = G
                .mul_tweak(&secp, &Scalar::from_be_bytes(t_n).unwrap())
                .unwrap();
            let reskey = res.combine(&B_m).unwrap();

            let mut resstr: String = reskey.to_string();
            resstr.drain(..2);

            let mut toAdd: HashMap<String, f32> = HashMap::new();

            toAdd.insert(resstr, amount);

            result.push(toAdd);

            n += 1;
        }
        // n += 1;
    }
    result
}
