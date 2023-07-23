use bech32::ToBase32;

use secp256k1::{hashes::Hash, Message, PublicKey, Scalar, Secp256k1, SecretKey, XOnlyPublicKey};
use std::{collections::HashMap, str::FromStr};

use crate::{input::ReceivingDataOutputs, sha256, utils::ser_uint32};

pub fn get_receiving_addresses(
    B_scan: PublicKey,
    B_spend: PublicKey,
    labels: &HashMap<String, String>,
) -> Vec<String> {
    let mut receiving_addresses: Vec<String> = vec![];
    receiving_addresses.push(encode_silent_payment_address(B_scan, B_spend, None, None));
    for (_, label) in labels {
        receiving_addresses.push(create_labeled_silent_payment_address(
            B_scan, B_spend, label, None, None,
        ));
    }

    receiving_addresses
}

pub fn derive_silent_payment_key_pair(
    bytes: &str,
    // _bytes: Vec<u8>,
) -> (SecretKey, SecretKey, PublicKey, PublicKey) {
    let secp = Secp256k1::new();

    // find fix for 1 byte array
    // let SPEND_KEY="m/352h/0h/0h/0h/0";
    // let SCAN_KEY="m/352h/0h/0h/1h/0";
    // let root_xpriv: ExtendedPrivateKey<SigningKey> = ExtendedPrivateKey::from_str("xprv9s21ZrQH143K4NfrUWWsMyZZichaQ6rEYoi9wFLSeiMJhnPCNQWmzbxdcacoxK7CUmvuCJWVKjNq26HcXTdUr3sMoDnMhU4e1i24sp8ZmmA").unwrap();
    // let scan_xpriv = XPrv::derive_from_path(&root_xpriv.to_bytes(), &SCAN_KEY.parse().unwrap()).unwrap();
    // let spend_xpriv = XPrv::derive_from_path(&root_xpriv.to_bytes(), &SPEND_KEY.parse().unwrap()).unwrap();
    // let scan_xpriv_priv = hex::encode(scan_xpriv.private_key().to_bytes());
    // let scan_xpriv_pub = hex::encode(scan_xpriv.public_key().to_bytes());

    let (b_scan_str, b_spend_str) = match bytes {
        "0x01" => (
            "a6dba5c9af3ee645c2287c6b1d558d3ea968502ef5343398f48715e624ddd183",
            "d96b8703387c5ffec5d256f80d4dc9f39152b2150fd05e469b011215251aa259",
        ),
        "0x00" => (
            "59984d7f53ff7e0ee345c6e9f5d5e47ae957abf3b55f2272152561db7e700255",
            "d41394c1c9dc1745c50028dc550765dfad87e50b3fdfb15a3e4290ec59ce34c6",
        ),
        "0x02" => (
            "34c45d7dc16b07aba41463fd5437fad2dd05e3da8afd1805ae13062882d4f7c4",
            "944d675e840f52af695d1415564912173b7a4ca740dc946875f9f64b97f8090c",
        ),
        _ => ("", ""),
    };

    let b_scan = SecretKey::from_str(b_scan_str).unwrap();
    let b_spend = SecretKey::from_str(b_spend_str).unwrap();

    let B_scan = b_scan.public_key(&secp);
    let B_spend = b_spend.public_key(&secp);
    (b_scan, b_spend, B_scan, B_spend)
}

pub fn get_A_sum_public_keys(input: &Vec<String>) -> PublicKey {
    let keys: Vec<PublicKey> = input
        .iter()
        .map(|x| match PublicKey::from_str(&x) {
            Ok(key) => key,
            Err(_) => {
                // we always assume even pairing for input public keys if they are omitted
                let x_only_public_key = XOnlyPublicKey::from_str(&x).unwrap();
                PublicKey::from_x_only_public_key(x_only_public_key, secp256k1::Parity::Even)
            }
        })
        .collect();
    let keys_refs: Vec<&PublicKey> = keys.iter().collect();

    PublicKey::combine_keys(&keys_refs).unwrap()
}

fn encode_silent_payment_address(
    B_scan: PublicKey,
    B_m: PublicKey,
    hrp: Option<&str>,
    version: Option<u8>,
) -> String {
    let hrp = hrp.unwrap_or("sp");
    let version = bech32::u5::try_from_u8(version.unwrap_or(0)).unwrap();

    let B_scan_bytes = B_scan.serialize();
    let B_m_bytes = B_m.serialize();

    let mut data = [B_scan_bytes, B_m_bytes].concat().to_base32();

    data.insert(0, version);

    bech32::encode(hrp, data, bech32::Variant::Bech32m).unwrap()
}

fn create_labeled_silent_payment_address(
    B_scan: PublicKey,
    B_spend: PublicKey,
    m: &String,
    hrp: Option<&str>,
    version: Option<u8>,
) -> String {
    let bytes = hex::decode(m).unwrap().try_into().unwrap();

    let scalar = Scalar::from_be_bytes(bytes).unwrap();
    let secp = Secp256k1::new();
    let G: PublicKey = SecretKey::from_slice(&Scalar::ONE.to_be_bytes())
        .unwrap()
        .public_key(&secp);
    let intermediate = G.mul_tweak(&secp, &scalar).unwrap();
    let B_m = intermediate.combine(&B_spend).unwrap();

    encode_silent_payment_address(B_scan, B_m, hrp, version)
}

fn calculate_P_n(B_spend: &PublicKey, t_n: [u8; 32]) -> PublicKey {
    let secp = Secp256k1::new();

    let G: PublicKey = SecretKey::from_slice(&Scalar::ONE.to_be_bytes())
        .unwrap()
        .public_key(&secp);
    let intermediate = G
        .mul_tweak(&secp, &Scalar::from_be_bytes(t_n).unwrap())
        .unwrap();
    let P_n = intermediate.combine(&B_spend).unwrap();

    P_n
}

fn calculate_t_n(ecdh_shared_secret: &[u8; 33], n: u32) -> [u8; 32] {
    let mut bytes: Vec<u8> = Vec::new();
    bytes.extend_from_slice(ecdh_shared_secret);
    bytes.extend_from_slice(&ser_uint32(n));
    crate::utils::sha256(&bytes)
}

fn calculate_ecdh_secret(
    A_sum: &PublicKey,
    b_scan: SecretKey,
    outpoints_hash: [u8; 32],
) -> [u8; 33] {
    let secp = Secp256k1::new();

    let intermediate = A_sum.mul_tweak(&secp, &b_scan.into()).unwrap();
    let scalar = Scalar::from_be_bytes(outpoints_hash).unwrap();
    let ecdh_shared_secret = intermediate.mul_tweak(&secp, &scalar).unwrap().serialize();

    ecdh_shared_secret
}

#[derive(Debug)]
pub struct WalletItem {
    pub pub_key: String,
    pub priv_key_tweak: String,
}

pub fn scanning(
    b_scan: SecretKey,
    B_spend: PublicKey,
    A_sum: PublicKey,
    outpoints_hash: [u8; 32],
    outputs_to_check: Vec<XOnlyPublicKey>,
    labels: Option<&HashMap<String, String>>,
) -> Vec<WalletItem> {
    let secp = secp256k1::Secp256k1::new();
    let ecdh_shared_secret = calculate_ecdh_secret(&A_sum, b_scan, outpoints_hash);
    let mut n = 0;
    let mut wallet: Vec<WalletItem> = vec![];

    let mut found = true;
    while found {
        found = false;
        let t_n = calculate_t_n(&ecdh_shared_secret, n);
        let P_n = calculate_P_n(&B_spend, t_n);
        let (P_n_xonly, _) = P_n.x_only_public_key();
        if outputs_to_check.iter().any(|&output| output.eq(&P_n_xonly)) {
            let pub_key = hex::encode(P_n_xonly.serialize());
            let priv_key_tweak = hex::encode(t_n);
            wallet.push(WalletItem {
                pub_key,
                priv_key_tweak,
            });
            n += 1;
            found = true;
        } else if let Some(labels) = labels {
            let P_n_negated = P_n.negate(&secp);
            for output in &outputs_to_check {
                let output_even = output.public_key(secp256k1::Parity::Even);
                let output_odd = output.public_key(secp256k1::Parity::Odd);

                // same as giving odd parity (?)
                // let output_negated = output_even.negate(&secp);

                let m_G_sub_even = output_even.combine(&P_n_negated).unwrap();
                let m_G_sub_odd = output_odd.combine(&P_n_negated).unwrap();
                let keys: Vec<PublicKey> = vec![m_G_sub_even, m_G_sub_odd];
                for labelkeystr in labels.keys() {
                    let labelkey = PublicKey::from_str(labelkeystr).unwrap();
                    if keys.iter().any(|x| x.eq(&labelkey)) {
                        let P_nm = hex::encode(output.serialize());
                        let label = labels.get(labelkeystr).unwrap();
                        let label_bytes = hex::decode(label).unwrap().try_into().unwrap();
                        let label_scalar = Scalar::from_be_bytes(label_bytes).unwrap();
                        let t_n_as_secret_key = SecretKey::from_slice(&t_n).unwrap();
                        let priv_key_tweak = hex::encode(
                            t_n_as_secret_key
                                .add_tweak(&label_scalar)
                                .unwrap()
                                .secret_bytes(),
                        );
                        wallet.push(WalletItem {
                            pub_key: P_nm,
                            priv_key_tweak,
                        });
                        n += 1;
                        found = true;
                    }
                }
            }
        }
    }
    wallet
}

pub fn verify_and_calculate_signatures(
    add_to_wallet: &mut Vec<WalletItem>,
    b_spend: SecretKey,
) -> Result<Vec<ReceivingDataOutputs>, secp256k1::Error> {
    let secp = secp256k1::Secp256k1::new();
    let msg = Message::from_hashed_data::<sha256::Hash>(b"message");
    let aux = sha256::Hash::hash(b"random auxiliary data").to_byte_array();

    let mut res: Vec<ReceivingDataOutputs> = vec![];
    for output in add_to_wallet {
        let pubkey = XOnlyPublicKey::from_str(&output.pub_key).unwrap();
        let tweak = hex::decode(&output.priv_key_tweak).unwrap();
        let scalar = Scalar::from_be_bytes(tweak.try_into().unwrap()).unwrap();
        let mut full_priv_key = b_spend.add_tweak(&scalar).unwrap();

        let (_, parity) = full_priv_key.x_only_public_key(&secp);

        if parity == secp256k1::Parity::Odd {
            full_priv_key = full_priv_key.negate();
        }

        let sig = secp.sign_schnorr_with_aux_rand(&msg, &full_priv_key.keypair(&secp), &aux);

        secp.verify_schnorr(&sig, &msg, &pubkey)?;

        res.push(ReceivingDataOutputs {
            pub_key: output.pub_key.to_string(),
            priv_key_tweak: output.priv_key_tweak.clone(),
            signature: sig.to_string(),
        });
    }
    Ok(res)
}
