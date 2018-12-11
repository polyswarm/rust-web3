//! `Personal` namespace

use api::Namespace;
use helpers::{self, CallFuture};
use types::{Address, H256, TransactionRequest};
use ethstore::accounts_dir::RootDiskDirectory;
use ethstore::{EthStore};
use Transport;

/// `Personal` namespace
#[derive(Debug, Clone)]
pub struct Personal<T> {
    transport: T,
}

impl<T: Transport> Namespace<T> for Personal<T> {
    fn new(transport: T) -> Self
    where
        Self: Sized,
    {
        Personal { transport }
    }

    fn transport(&self) -> &T {
        &self.transport
    }
}

impl<T: Transport> Personal<T> {
    /// Returns a list of available accounts.
    pub fn list_accounts(&self) -> CallFuture<Vec<Address>, T::Out> {
        CallFuture::new(self.transport.execute("personal_listAccounts", vec![]))
    }

    /// Creates a new account and protects it with given password.
    /// Returns the address of created account.
    pub fn new_account(&self, password: &str) -> CallFuture<Address, T::Out> {
        let password = helpers::serialize(&password);
        CallFuture::new(
            self.transport
                .execute("personal_newAccount", vec![password]),
        )
    }

    /// Unlocks the account with given password for some period of time (or single transaction).
    /// Returns `true` if the call was successful.
    pub fn unlock_account(&self, address: Address, password: &str, duration: Option<u16>) -> CallFuture<bool, T::Out> {
        let address = helpers::serialize(&address);
        let password = helpers::serialize(&password);
        let duration = helpers::serialize(&duration);
        CallFuture::new(
            self.transport
                .execute("personal_unlockAccount", vec![address, password, duration]),
        )
    }

    /// Get keyfile stores
    /// Returns Store of all the keyfiles in keydir
    pub fn get_store_for_keyfiles(&self, keyfile_dir: &str) -> EthStore {
        let path = match ::std::fs::metadata(keyfile_dir) {
            Ok(_) => keyfile_dir.into(),
            Err(_) => "",
        };
        let dir = RootDiskDirectory::at(path);
        EthStore::open(Box::new(dir)).unwrap()
    }

    /// Sends a transaction from locked account.
    /// Returns transaction hash.
    pub fn send_transaction(&self, transaction: TransactionRequest, password: &str) -> CallFuture<H256, T::Out> {
        let transaction = helpers::serialize(&transaction);
        let password = helpers::serialize(&password);
        CallFuture::new(
            self.transport
                .execute("personal_sendTransaction", vec![transaction, password]),
        )
    }


}

#[cfg(test)]
mod tests {
    use futures::Future;

    use api::Namespace;
    use rpc::Value;
    use ethcore_transaction::{Action, Transaction as RawTransactionRequest};
    use types::{TransactionRequest};
    use ethstore::ethkey::{KeyPair, verify_address};
    use ethkey::Message;
    use ethstore::{SimpleSecretStore, StoreAccountRef};
    use helpers::tests::TestTransport;
    use std::str::FromStr;
    use super::Personal;

    rpc_test! (
    Personal:list_accounts => "personal_listAccounts";
    Value::Array(vec![Value::String("0x0000000000000000000000000000000000000123".into())]) => vec![0x123.into()]
  );

    rpc_test! (
    Personal:new_account, "hunter2" => "personal_newAccount", vec![r#""hunter2""#];
    Value::String("0x0000000000000000000000000000000000000123".into()) => 0x123
  );

    rpc_test! (
    Personal:unlock_account, 0x123, "hunter2", None
    =>
    "personal_unlockAccount", vec![r#""0x0000000000000000000000000000000000000123""#, r#""hunter2""#, r#"null"#];
    Value::Bool(true) => true
  );

    rpc_test! (
    Personal:send_transaction, TransactionRequest {
      from: 0x123.into(), to: Some(0x123.into()),
      gas: None, gas_price: Some(0x1.into()),
      value: Some(0x1.into()), data: None,
      nonce: None, condition: None,
    }, "hunter2"
    =>
    "personal_sendTransaction", vec![r#"{"from":"0x0000000000000000000000000000000000000123","gasPrice":"0x1","to":"0x0000000000000000000000000000000000000123","value":"0x1"}"#, r#""hunter2""#];
    Value::String("0x0000000000000000000000000000000000000000000000000000000000000123".into()) => 0x123
  );

    #[test]
    fn test_keyfile_store() {
        let transport = TestTransport::default();
        let personal = Personal::new(&transport);
        let kp1 = KeyPair::from_secret("000081c29e8142bb6a81bef5a92bda7a8328a5c85bb2f9542e76f9b0f94fc018".parse().unwrap()).unwrap();
        let store = personal.get_store_for_keyfiles(&"src/api/test/keyfiles");
        let accounts = store.accounts().unwrap();
        let message = Message::from_str("8378603b0ac95d711b8863cb869e5fa6983438aa1977a767f63d9d3f7f941caf").unwrap();
        let s1 = store.sign(&accounts[0], &"foo".into(), &message).unwrap();

        assert_eq!(accounts, vec![
            StoreAccountRef::root("31e9d1e6d844bd3a536800ef8d8be6a9975db509".into()),
        ]);

        assert!(verify_address(&accounts[0].address, &s1, &message).unwrap());
        assert!(verify_address(&kp1.address(), &s1, &message).unwrap());
    }

    #[test]
    fn test_keyfile_tx_signature() {
        let transport = TestTransport::default();
        let personal = Personal::new(&transport);
        let store = personal.get_store_for_keyfiles(&"src/api/test/keyfiles");
        let accounts = store.accounts().unwrap();
        
        assert_eq!(accounts, vec![
            StoreAccountRef::root("31e9d1e6d844bd3a536800ef8d8be6a9975db509".into()),
        ]);

        let tx_request = RawTransactionRequest {
            nonce: 0.into(),
            gas_price: 42.into(),
            gas: 69.into(),
            action: Action::Call("0x0000000000000000000000000000000000000000".into()),
            value: 1337.into(),
            data: vec![],
        };

        let chain_id = 1338;
        let tx_hash = tx_request.hash(Some(chain_id));
        let password = "foo";
        let signature = store.sign(&accounts[0], &password.into(), &tx_hash).unwrap();
        let _tx_rlp = tx_request.with_signature(signature, Some(chain_id));

    }

}