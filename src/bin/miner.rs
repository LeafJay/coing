mod wallet;

use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fs::File,
    io::Write,
    sync::{Arc, Mutex},
};

use p256::ecdsa::signature::Verifier;
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    net::{TcpListener, TcpStream},
};
use wallet::{key_to_address, SentTransaction, Transaction};

type Pool = Arc<Mutex<Vec<Transaction>>>;
type Utxos = HashMap<UtxoKey, u64>;
type UtxosDB = Arc<Mutex<Utxos>>;
type PreviousBlockHash = Arc<Mutex<[u8; 32]>>;

const BLOCK_SIZE: usize = 1;
const DIFFICULTY: usize = 2;
const REWARD: u64 = 50;
const COINBASE_ADDRESS: &str = "17PZXzLrz95TdPr4CuStYboxtjc6tYrU6V";

#[derive(PartialEq, Eq, Hash, Clone, Debug, Serialize, Deserialize)]
pub struct UtxoKey {
    txid: String,
    address: String,
}

#[tokio::main]
async fn main() {
    let pool: Pool = Arc::new(Mutex::new(Vec::new()));
    let utxos: UtxosDB = Arc::new(Mutex::new(HashMap::new()));

    utxos.lock().unwrap().insert(
        UtxoKey {
            txid: "genesis".to_string(),
            address: COINBASE_ADDRESS.to_string(),
        },
        100,
    );

    let previous_block_hash: PreviousBlockHash = Arc::new(Mutex::new([0; 32]));
    let listener = TcpListener::bind("127.0.0.1:11111").await.unwrap();

    loop {
        let (socket, _) = listener.accept().await.unwrap();
        let pool = pool.clone();
        let utxos = utxos.clone();
        let previous_block_hash = previous_block_hash.clone();
        tokio::spawn(async move {
            process(socket, pool, utxos, previous_block_hash).await;
        });
    }
}

async fn process(
    stream: TcpStream,
    pool: Pool,
    utxos: UtxosDB,
    previous_block_hash: PreviousBlockHash,
) {
    let reader = BufReader::new(stream);
    let mut lines = reader.lines();
    while let Some(line) = lines.next_line().await.expect("failed to read line") {
        let sent_transaction: SentTransaction =
            serde_json::from_str(&line).expect("failed to parse");
        let mut utxos = utxos.lock().unwrap();
        if verify_transaction(&sent_transaction, &mut utxos) {
            println!("transaction is valid");
            let mut pool = pool.lock().unwrap();
            commit_transaction(sent_transaction, &mut utxos, &mut pool);
            if pool.len() >= BLOCK_SIZE {
                if let Ok(mut previous_block_hash) = previous_block_hash.lock() {
                    let block_transactions = pool.drain(..BLOCK_SIZE).collect::<Vec<_>>();
                    mine(block_transactions, &mut previous_block_hash, &mut utxos);
                }
            }
        } else {
            println!("transaction is invalid");
        }
    }
}

fn verify_transaction(sent_transaction: &SentTransaction, utxos: &mut Utxos) -> bool {
    let mut correct = true;
    if Verifier::verify(
        &sent_transaction.verifying_key,
        sent_transaction.transaction.txid.as_bytes(),
        &sent_transaction.transaction.signature,
    )
    .is_err()
    {
        return false;
    }

    let sender = key_to_address(&sent_transaction.verifying_key);

    let mut output_total = 0;
    let mut input_total = 0;
    sent_transaction
        .transaction
        .outputs
        .iter()
        .for_each(|output| {
            output_total += output.amount;
        });

    sent_transaction
        .transaction
        .inputs
        .iter()
        .for_each(|input| {
            if let Some(amount) = utxos.get(&UtxoKey {
                txid: input.clone(),
                address: sender.clone(),
            }) {
                input_total += amount;
            } else {
                correct = false;
            }
        });

    if input_total != output_total {
        correct = false;
    }

    correct
}

fn commit_transaction(
    sent_transaction: SentTransaction,
    utxos: &mut Utxos,
    pool: &mut Vec<Transaction>,
) {
    let sender = key_to_address(&sent_transaction.verifying_key);
    sent_transaction
        .transaction
        .inputs
        .iter()
        .for_each(|input| {
            utxos.remove(&UtxoKey {
                txid: input.clone(),
                address: sender.clone(),
            });
        });

    sent_transaction
        .transaction
        .outputs
        .iter()
        .for_each(|output| {
            utxos.insert(
                UtxoKey {
                    txid: sent_transaction.transaction.txid.clone(),
                    address: output.recipient.clone(),
                },
                output.amount,
            );
        });
    pool.push(sent_transaction.transaction);
}

fn mine(
    block_transactions: Vec<Transaction>,
    previous_block_hash: &mut [u8; 32],
    utxos: &mut Utxos,
) {
    let mut block: [u8; 32];
    let mut nonce = 0;

    let serialized_transactions =
        serde_json::to_string(&block_transactions).expect("failed to serialize transactions");

    let mut hasher = <Sha256 as Digest>::new();
    let time = chrono::Utc::now().timestamp();
    loop {
        let input = format!(
            "{}\n{}\n{}\n{}\n{}\n{}\n",
            nonce,
            time,
            COINBASE_ADDRESS,
            REWARD,
            serialized_transactions,
            hex::encode(&previous_block_hash),
        );
        hasher.update(input.as_bytes());
        block = hasher.finalize_reset().into();
        if block.starts_with(&[0; DIFFICULTY]) {
            println!("block mined: {}", hex::encode(block));
            *previous_block_hash = block;
            utxos.insert(
                UtxoKey {
                    txid: hex::encode(block),
                    address: COINBASE_ADDRESS.to_string(),
                },
                REWARD,
            );
            let mut file = File::create(format!("blocks/{}.coing", hex::encode(block)))
                .expect("failed to create file");
            file.write_all(input.as_bytes())
                .expect("failed to write to file");
            // file.write_all(
            //     serde_json::to_string(utxos)
            //         .expect("failed to serialize utxos")
            //         .as_bytes(),
            // )
            // .expect("failed to write to file");
            break;
        }

        nonce += 1;
    }
}
