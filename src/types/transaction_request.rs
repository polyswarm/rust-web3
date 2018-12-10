use types::{Address, Bytes, U256, H256};
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
use tiny_keccak::keccak256;
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

/// A set of information describing an externally-originating message call
/// or contract creation operation.
#[derive(Default, Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RawTransactionRequest {
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
    pub data: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<U256>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chain_id: Option<u64>,


}

impl Decodable for RawTransactionRequest {
    fn decode(d: &Rlp) -> Result<Self, DecoderError> {
        if d.item_count()? != 6 {
            return Err(DecoderError::RlpIncorrectListLen);
        }
        let hash = keccak256(d.as_raw());
        Ok(RawTransactionRequest {
            nonce: d.val_at(0)?,
            gas_price: d.val_at(1)?,
            gas: d.val_at(2)?,
            to: d.val_at(3)?,
            value: d.val_at(4)?,
            data: d.val_at(5)?,
            chain_id: d.val_at(6)?,
        })
    }
}

impl rlp::Encodable for RawTransactionRequest {
    fn rlp_append(&self, s: &mut RlpStream) {
        self.rlp_append_unsigned_transaction(s)
    }
}

impl RawTransactionRequest {
    /// Append object with a without signature into RLP stream
    pub fn rlp_append_unsigned_transaction(&self, s: &mut RlpStream) {
        s.begin_list(if self.chain_id.is_none() { 6 } else { 9 });
        s.append(&self.nonce);
        s.append(&self.gas_price);
        s.append(&self.gas);
        s.append(&self.to);
        s.append(&self.value);
        s.append(&self.data);

        if let Some(n) = self.chain_id {
            s.append(&n);
            s.append(&0u8);
            s.append(&0u8);
        }
    }

    pub fn rlp_bytes(&self) -> Vec<u8> {
        let mut s: RlpStream = RlpStream::new();
        self.rlp_append_unsigned_transaction(&mut s);
        s.as_raw().to_vec()
    }

    pub fn hash(&self) -> H256 {
        let mut s: RlpStream = RlpStream::new();
        self.rlp_append_unsigned_transaction(&mut s);
        H256::from(keccak256(s.as_raw()))
    }

    /// Signs the transaction with signature.
    pub fn with_signature(self, sig: &Signature) -> Vec<u8> {
        let mut s: RlpStream = RlpStream::new();

        UnverifiedTransaction {
            r: sig.r().into(),
            s: sig.s().into(),
            v: signature::add_chain_replay_protection(sig.v().into(), Some(self.chain_id.unwrap())),
            hash: self.hash(),
            unsigned: self,
        }.rlp_append(&mut s);
        s.as_raw().to_vec()
    }
}

/// Signed RawTransactionRequest information without verified signature.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct UnverifiedTransaction {
    /// Plain Transaction.
    unsigned: RawTransactionRequest,
    /// The V field of the signature; the LS bit described which half of the curve our point falls
    /// in. The MS bits describe which chain this RawTransactionRequest is for. If 27/28, its for all chains.
    v: u64,
    /// The R field of the signature; helps describe the point on the curve.
    r: U256,
    /// The S field of the signature; helps describe the point on the curve.
    s: U256,
    /// Hash of the transaction
    hash: H256,
}

impl Decodable for UnverifiedTransaction {
    fn decode(d: &Rlp) -> Result<Self, DecoderError> {
        if d.item_count()? != 9 {
            return Err(DecoderError::RlpIncorrectListLen);
        }
        let hash = keccak256(d.as_raw());
        Ok(UnverifiedTransaction {
            unsigned: RawTransactionRequest {
                nonce: d.val_at(0)?,
                gas_price: d.val_at(1)?,
                gas: d.val_at(2)?,
                to: d.val_at(3)?,
                value: d.val_at(4)?,
                data: d.val_at(5)?,
                chain_id: d.val_at(6)?,
            },
            v: d.val_at(6)?,
            r: d.val_at(7)?,
            s: d.val_at(8)?,
            hash: hash.into(),
        })
    }
}

impl rlp::Encodable for UnverifiedTransaction {
    fn rlp_append(&self, s: &mut RlpStream) {
        self.rlp_append_sealed_transaction(s)
    }
}

/// Replay protection logic for v part of transaction's signature
pub mod signature {
    /// Adds chain id into v
    pub fn add_chain_replay_protection(v: u64, chain_id: Option<u64>) -> u64 {
        v + if let Some(n) = chain_id { 35 + n * 2 } else { 27 }
    }
}


impl UnverifiedTransaction {
    /// Used to compute hash of created transactions
    fn compute_hash(mut self) -> UnverifiedTransaction {
        let hash = keccak256(&*self.rlp_bytes());
        self.hash = hash.into();
        self
    }

    /// Checks is signature is empty.
    pub fn is_unsigned(&self) -> bool {
        self.r.is_zero() && self.s.is_zero()
    }

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

    /// Reference to unsigned part of this transaction.
    pub fn as_unsigned(&self) -> &RawTransactionRequest {
        &self.unsigned
    }

    /// The `v` value that appears in the RLP.
    pub fn original_v(&self) -> u64 {
        self.v
    }

    /// The chain ID, or `None` if this is a global transaction.
    pub fn chain_id(&self) -> Option<u64> {
        match self.v {
            v if self.is_unsigned() => Some(v),
            v if v >= 35 => Some((v - 35) / 2),
            _ => None,
        }
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
    use rlp::{RlpStream};
    use types::{H256, U256, Address};
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
            nonce: Some(U256::from(0)),
            gas_price: Some(42.into()),
            gas: Some(69.into()),
            to: Some("0x0000000000000000000000000000000000000000".into()),
            value: Some(1337.into()),
            data: Some(vec![]),
            chain_id: None,
        };

        let tx_hash = tx_request.hash();
        let rlp_bytes = tx_request.rlp_bytes();

        println!("Printing rlp_bytes");
        println!("{:x?}", rlp_bytes);

        /// Prints
        /// [e2, c1, 80, c1, 2a, c1, 45, d5, 94, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, c3, 82, 5, 39, c1, 80]

        /// Should be (from ethcore)
        /// [df, 80, 2a, 45, 94, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 82, 5, 39, 80, 1b, 1, 2]

        let mut s = RlpStream::new();
        s.append(&tx_hash);
        println!("RAW rlp");
        println!("{:x?}", s.out());

        /// Prints
        /// [a0, 36, 9b, f7, 2c, 4e, ef, 5c, 10, fd, 50, 2d, 80, d2, 78, de, 99, d5, 94, b7, b8, f2, 93, f, 93, 6c, 2b, a8, cc, a7, ed, f4, a0]

        /// Should be (from ethcore)
        /// [df, 80, 2a, 45, 94, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 82, 5, 39, 80, 1b, 1, 2]


        assert_eq!(
            tx_hash,
            H256::from_str("b40b938c97a58418693ba8d24641ec2a654fc6345eafdc364a3faf557d364347").unwrap()
        );
    }
}

