use types::{Address, Bytes, U256, H256};
use tiny_keccak::keccak256;
use rlp::{RlpStream};
use ethkey::{Signature};

/// Call contract request (eth_call / eth_estimateGas)
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct CallRequest {
    /// Sender address (None for arbitrary address)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<Address>,
    /// To address
    pub to: Address,
    /// Supplied gas (None for sensible default)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gas: Option<U256>,
    /// Gas price (None for sensible default)
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "gasPrice")]
    pub gas_price: Option<U256>,
    /// Transfered value (None for no transfer)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<U256>,
    /// Data (None for empty data)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Bytes>,
}

/// Send Transaction Parameters
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RawTransactionRequest {
    /// Sender address
    pub from: Address,
    /// chain id
    pub chain_id: u64,
    /// Recipient address (None for contract creation)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to: Option<Address>,
    /// Supplied gas (None for sensible default)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gas: Option<U256>,
    /// Gas price (None for sensible default)
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "gasPrice")]
    pub gas_price: Option<U256>,
    /// Transfered value (None for no transfer)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<U256>,
    /// Transaction data (None for empty bytes)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Bytes>,
    /// Transaction nonce (None for next available nonce)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<U256>,
    /// Min block inclusion (None for include immediately)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub condition: Option<TransactionCondition>,
}

/// Signed transaction information without verified signature.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct UnverifiedTransaction {
    unsigned: RawTransactionRequest,
    v: u64,
    r: U256,
    s: U256,
}


impl RawTransactionRequest {
    /// From ethereum parity
    /// EIP155 spec:
    /// when computing the hash of a transaction for purposes of signing or recovering,
    /// instead of hashing only the first six elements (ie. nonce, gasprice, startgas, to, value, data),
    /// hash nine elements, with v replaced by CHAIN_ID, r = 0 and s = 0
    /// Append object with a without signature into RLP stream
    pub fn rlp_append_unsigned_transaction(&self, s: &mut RlpStream) {
        s.begin_unbounded_list();
        s.append(&self.nonce);
        s.append(&self.gas_price);
        s.append(&self.gas);
        s.append(&self.to);
        s.append(&self.value);
        s.append(&self.data);
        s.append(&self.chain_id);
        s.append(&0u8);
        s.append(&0u8);
        s.complete_unbounded_list();
    }

    /// The message hash of the transaction.
    pub fn hash(&self) -> H256 {
        let mut stream = RlpStream::new();
        self.rlp_append_unsigned_transaction(&mut stream);

        H256::from(keccak256(&stream.out()))
    }

    /// Signs the transaction with signature.
    pub fn with_signature(self, sig: Signature) -> Bytes {
        UnverifiedTransaction {
            r: sig.r().into(),
            s: sig.s().into(),
            v: signature::add_chain_replay_protection(sig.v().into(), Some(self.chain_id.into())),
            unsigned: self,
        }.tx_bytes()
    }


}

/// Replay protection logic for v part of transaction's signature
pub mod signature {
    /// Adds chain id into v
    pub fn add_chain_replay_protection(v: u64, chain_id: Option<u64>) -> u64 {
        v + if let Some(n) = chain_id { 35 + n * 2 } else { 27 }
    }
}

impl rlp::Encodable for UnverifiedTransaction {
    fn rlp_append(&self, s: &mut RlpStream) { self.rlp_append_sealed_transaction(s) }
}

impl UnverifiedTransaction {
    /// Append object with a signature into RLP stream
    fn rlp_append_sealed_transaction(&self, s: &mut RlpStream) {
        s.begin_list(9);
        s.append(&self.unsigned.nonce);
        s.append(&self.unsigned.gas_price);
        s.append(&self.unsigned.gas);
        s.append(&self.unsigned.to);
        s.append(&self.unsigned.value);
        s.append(&self.unsigned.data);
        s.append(&self.v);
        s.append(&self.r);
        s.append(&self.s);
    }

    /// Get the hash of this transaction (keccak of the RLP).
    pub fn tx_bytes(&self) -> Bytes {
        let mut stream = RlpStream::new();
        self.rlp_append_sealed_transaction(&mut stream);
        println!("h256 of tx_bytes");
        println!("{:?}", H256::from(stream.as_raw()));
        Bytes(stream.as_raw().to_vec())
    }

}

/// Send Transaction Parameters
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct TransactionRequest {
    /// Sender address
    pub from: Address,
    /// Recipient address (None for contract creation)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to: Option<Address>,
    /// Supplied gas (None for sensible default)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gas: Option<U256>,
    /// Gas price (None for sensible default)
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "gasPrice")]
    pub gas_price: Option<U256>,
    /// Transfered value (None for no transfer)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<U256>,
    /// Transaction data (None for empty bytes)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Bytes>,
    /// Transaction nonce (None for next available nonce)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<U256>,
    /// Min block inclusion (None for include immediately)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub condition: Option<TransactionCondition>,
}

/// Represents condition on minimum block number or block timestamp.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum TransactionCondition {
    /// Valid at this minimum block number.
    #[serde(rename = "block")]
    Block(u64),
    /// Valid at given unix time.
    #[serde(rename = "time")]
    Timestamp(u64),
}

#[cfg(test)]
mod tests {
    use serde_json;
    use super::{CallRequest, TransactionCondition, TransactionRequest, RawTransactionRequest};
    use types::{H256};
    use std::str::FromStr;

    #[test]
    fn should_serialize_call_request() {
        // given
        let call_request = CallRequest {
            from: None,
            to: 5.into(),
            gas: Some(21_000.into()),
            gas_price: None,
            value: Some(5_000_000.into()),
            data: Some(vec![1, 2, 3].into()),
        };

        // when
        let serialized = serde_json::to_string_pretty(&call_request).unwrap();

        // then
        assert_eq!(
            serialized,
            r#"{
  "to": "0x0000000000000000000000000000000000000005",
  "gas": "0x5208",
  "value": "0x4c4b40",
  "data": "0x010203"
}"#
        );
    }

    #[test]
    fn should_serialize_transaction_request() {
        // given
        let tx_request = TransactionRequest {
            from: 5.into(),
            to: None,
            gas: Some(21_000.into()),
            gas_price: None,
            value: Some(5_000_000.into()),
            data: Some(vec![1, 2, 3].into()),
            nonce: None,
            condition: Some(TransactionCondition::Block(5)),
        };

        // when
        let serialized = serde_json::to_string_pretty(&tx_request).unwrap();

        // then
        assert_eq!(
            serialized,
            r#"{
  "from": "0x0000000000000000000000000000000000000005",
  "gas": "0x5208",
  "value": "0x4c4b40",
  "data": "0x010203",
  "condition": {
    "block": 5
  }
}"#
        );
    }

    #[test]
    fn should_get_tx() {
        let tx_request = RawTransactionRequest {
            from: 5.into(),
            to: None,
            chain_id: 1338,
            gas: Some(21_000.into()),
            gas_price: None,
            value: Some(5_000_000.into()),
            data: Some(vec![1, 2, 3].into()),
            nonce: None,
            condition: Some(TransactionCondition::Block(5)),
        };

        let tx_hash = tx_request.hash();

        assert_eq!(
            tx_hash,
            H256::from_str("ea5741b6688031897f75ff78801c5acebe2a477c711a22d9d19e136650087241").unwrap()
        );
    }
}

