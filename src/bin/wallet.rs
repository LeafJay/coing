use std::{io::Write, net::TcpStream};

use p256::{
    ecdsa::{signature::Signer, Signature, SigningKey, VerifyingKey},
    pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey},
};
use ripemd::Ripemd160;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

fn main() {
    //generate_key("eva");
    let signing_key_jay: SigningKey =
        DecodePrivateKey::read_pkcs8_pem_file("jay").expect("failed to read key");
    let signing_key_eva: SigningKey =
        DecodePrivateKey::read_pkcs8_pem_file("eva").expect("failed to read key");
    let address_jay = key_to_address(signing_key_jay.verifying_key());
    let address_eva = key_to_address(signing_key_eva.verifying_key());

    let (transaction, v_key) =
        generate_p2pkh_transaction(signing_key_jay.clone(), address_eva.clone(), 50).unwrap();
    println!("transaction: {:?}", transaction);
    send_transaction(transaction, v_key);
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SentTransaction {
    pub transaction: Transaction,
    pub verifying_key: VerifyingKey,
}

fn send_transaction(transaction: Transaction, verifying_key: VerifyingKey) {
    let serialized_transaction = serde_json::to_string(&SentTransaction {
        transaction,
        verifying_key,
    })
    .expect("failed to serialize transaction");
    let mut stream = TcpStream::connect("127.0.0.1:11111").expect("failed to connect");
    stream
        .write_all(serialized_transaction.as_bytes())
        .expect("failed to write");
}

fn generate_key(name: &str) {
    let mut rng = rand::thread_rng();
    let private_key = SigningKey::random(&mut rng);
    EncodePrivateKey::write_pkcs8_pem_file(&private_key, name, p256::pkcs8::LineEnding::LF)
        .expect("failed to write key");
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Transaction {
    pub txid: String,
    pub signature: Signature,
    pub inputs: Vec<String>,
    pub outputs: Vec<Output>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Output {
    pub recipient: String,
    pub amount: u64,
}

fn generate_p2pkh_transaction(
    signing_key: SigningKey,
    recepient: String,
    amount: u64,
) -> Option<(Transaction, VerifyingKey)> {
    let sender_address = key_to_address(signing_key.verifying_key());
    let utxos = get_utxos(&sender_address);
    let mut inputs_amount = 0;
    let inputs = utxos
        .iter()
        .filter_map(|(txid, input_amount)| {
            if inputs_amount < amount {
                inputs_amount += input_amount;
                Some(txid.to_string())
            } else {
                None
            }
        })
        .collect::<Vec<_>>();

    if inputs_amount < amount {
        return None;
    }

    let mut outputs = vec![Output {
        recipient: recepient.clone(),
        amount,
    }];

    if inputs_amount > amount {
        outputs.push(Output {
            recipient: sender_address,
            amount: inputs_amount - amount,
        });
    }

    let txid = hash_txid(&inputs, &outputs);
    let signature: Signature = signing_key.sign(txid.as_bytes());

    let verifying_key = signing_key.verifying_key();

    let transaction = Transaction {
        txid,
        signature,
        inputs,
        outputs,
    };

    Some((transaction, *verifying_key))
}

fn get_utxos(address: &str) -> Vec<(String, u64)> {
    vec![(String::from(""), 50)]
}

pub fn key_to_address(public_key: &VerifyingKey) -> String {
    let der = EncodePublicKey::to_public_key_der(public_key).expect("failed to encode key");
    let ripemd160 = <Ripemd160 as Digest>::digest(<Sha256 as Digest>::digest(der.as_bytes()));
    let mut adr = ripemd160.to_vec();
    adr.insert(0, 0);
    let checksum = <Sha256 as Digest>::digest(<Sha256 as Digest>::digest(adr.clone()));
    adr.extend_from_slice(&checksum[..4]);
    bs58::encode(adr).into_string()
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct TransactionData {
    inputs: Vec<String>,
    outputs: Vec<Output>,
}

fn hash_txid(inputs: &Vec<String>, outputs: &[Output]) -> String {
    let serialized_transaction = serde_json::to_string(&TransactionData {
        inputs: inputs.clone(),
        outputs: outputs.to_vec(),
    })
    .expect("failed to serialize inputs");

    hex::encode(<Sha256 as Digest>::digest(
        serde_json::to_string(&serialized_transaction)
            .expect("failed to serialize inputs")
            .as_bytes(),
    ))
}
