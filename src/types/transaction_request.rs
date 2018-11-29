use types::{Address, Bytes, U256, H256};
use hash::keccak;
use rlp::{RlpStream};

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
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct RawTransactionRequest {
    /// Sender address
    pub from: Address,
    /// chain id
    pub chain_id: usize,
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


impl RawTransactionRequest {
    /// From eth parity
    /// Append object with a without signature into RLP stream
    pub fn rlp_append_unsigned_transaction(&self, s: &mut RlpStream) {
        s.begin_list(self.chain_id);
        s.append(&self.nonce);
        s.append(&self.gas_price);
        s.append(&self.gas);
        s.append(&self.data);
        s.append(&self.value);
    }

    /// The message hash of the transaction.
    pub fn hash(&self) -> H256 {
        let mut stream = RlpStream::new();
        self.rlp_append_unsigned_transaction(&mut stream);
        keccak(stream.as_raw())
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
        // given
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
            H256::from_str("8378603b0ac95d711b8863cb869e5fa6983438aa1977a767f63d9d3f7f941caf").unwrap()
        );
    }
}
