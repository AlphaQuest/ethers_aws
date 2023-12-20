pub mod aws_signer_error;
mod utils;

use async_trait::async_trait;
use aws_config::{BehaviorVersion, Region};
use aws_sdk_kms::{config::Credentials, primitives::Blob, Client};
use ethers::{
    signers::{to_eip155_v, Signer},
    types::{
        transaction::{eip2718::TypedTransaction, eip712::Eip712},
        Address, Signature, H256,
    },
    utils::hash_message,
};

use self::{
    aws_signer_error::AWSSignerError,
    utils::{
        correct_eth_sig_r_value, correct_s_for_malleability, decode_der_signature,
        get_ethereum_address,
    },
};

#[derive(Clone, Debug)]
pub struct AWSSigner {
    pub client: Client,
    pub key_id: String,
    pub address: Address,
    pub chain_id: u64,
}

impl AWSSigner {
    /**
     * Creates a new AWSSigner
     */
    pub async fn new(
        chain_id: u64,
        access_key: String,
        secret_access_key: String,
        key_id: String,
        region: String,
    ) -> Result<Self, aws_signer_error::AWSSignerError> {
        let region = Region::new(region);
        let shared_config = aws_config::defaults(BehaviorVersion::v2023_11_09())
            .region(region)
            .credentials_provider(Credentials::new(
                access_key,
                secret_access_key,
                None,
                None,
                "",
            ))
            .load()
            .await;
        let client = Client::new(&shared_config);
        let address = get_ethereum_address(&client, &key_id).await?;
        log::debug!("AWS Signer created. Address {:?}", address);
        Ok(Self {
            client,
            address,
            key_id,
            chain_id,
        })
    }

    // Sign the hash of the message
    async fn sign_hash(&self, hash: H256) -> Result<Signature, AWSSignerError> {
        let eth_signature = decode_der_signature(
            self.client
                .sign()
                .key_id(&self.key_id)
                .message(Blob::new(hash.as_bytes()))
                .message_type(aws_sdk_kms::types::MessageType::Digest)
                .signing_algorithm(aws_sdk_kms::types::SigningAlgorithmSpec::EcdsaSha256)
                .send()
                .await
                .map_err(|e| AWSSignerError::SdkError(format!("{:?}", e)))?
                .signature()
                .ok_or(AWSSignerError::SdkError(
                    "Missing signature in response".to_owned(),
                ))?
                .as_ref(),
        )?;
        let eth_signature = correct_s_for_malleability(eth_signature)?;
        let eth_signature = correct_eth_sig_r_value(eth_signature, hash, self.address)?;
        Ok(eth_signature)
    }

    /// Synchronously signs the provided transaction, normalizing the signature `v` value with
    /// EIP-155 using the transaction's `chain_id`, or the signer's `chain_id` if the transaction
    /// does not specify one.
    async fn sign_transaction_async(
        &self,
        tx: &TypedTransaction,
    ) -> Result<Signature, AWSSignerError> {
        // rlp (for sighash) must have the same chain id as v in the signature
        let chain_id = tx.chain_id().map(|id| id.as_u64()).unwrap_or(self.chain_id);
        let mut tx = tx.clone();
        tx.set_chain_id(chain_id);

        let sighash = tx.sighash();
        let mut sig = self.sign_hash(sighash).await?;

        // sign_hash sets `v` to recid + 27, so we need to subtract 27 before normalizing
        sig.v = to_eip155_v(sig.v as u8 - 27, chain_id);
        Ok(sig)
    }
}

#[async_trait]
impl Signer for AWSSigner {
    type Error = AWSSignerError;
    async fn sign_transaction(&self, tx: &TypedTransaction) -> Result<Signature, Self::Error> {
        let mut tx_with_chain = tx.clone();
        if tx_with_chain.chain_id().is_none() {
            // in the case we don't have a chain_id, let's use the signer chain id instead
            tx_with_chain.set_chain_id(self.chain_id);
        }
        self.sign_transaction_async(&tx_with_chain).await
    }
    async fn sign_message<S: Send + Sync + AsRef<[u8]>>(
        &self,
        message: S,
    ) -> Result<Signature, Self::Error> {
        let message = message.as_ref();
        let message_hash = hash_message(message);
        self.sign_hash(message_hash).await
    }

    /// Encodes and signs the typed data according EIP-712.
    /// Payload must implement Eip712 trait.
    async fn sign_typed_data<T: Eip712 + Send + Sync>(
        &self,
        payload: &T,
    ) -> Result<Signature, Self::Error> {
        let encoded = payload
            .encode_eip712()
            .map_err(|e| Self::Error::Eip712Error(e.to_string()))?;
        self.sign_hash(H256::from(encoded)).await
    }

    /// Returns the signer's Ethereum Address
    fn address(&self) -> Address {
        self.address
    }

    /// Returns the signer's chain id
    fn chain_id(&self) -> u64 {
        self.chain_id
    }

    /// Sets the signer's chain id
    #[must_use]
    fn with_chain_id<T: Into<u64>>(self, chain_id: T) -> Self {
        Self {
            client: self.client,
            key_id: self.key_id,
            address: self.address,
            chain_id: chain_id.into(),
        }
    }
}

#[cfg(test)]
mod tests {

    use ethers::signers::Signer;
    use ethers::types::{Eip1559TransactionRequest, U256};
    use ethers::utils::parse_units;

    use super::AWSSigner;

    #[tokio::test]
    async fn create_aws_signer() {
        let access_key = std::env::var("ACCESS_KEY").expect("ACCESS_KEY must be in environment");
        let secret_access_key =
            std::env::var("SECRET_ACCESS_KEY").expect("SECRET_ACCESS_KEY must be in environment");
        let key_id: String = std::env::var("KEY_ID").expect("KEY_ID must be in environment");
        let region = std::env::var("REGION").expect("REGION must be in environment");
        AWSSigner::new(1, access_key, secret_access_key, key_id, region)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_sign_message() {
        let access_key = std::env::var("ACCESS_KEY").expect("ACCESS_KEY must be in environment");
        let secret_access_key =
            std::env::var("SECRET_ACCESS_KEY").expect("SECRET_ACCESS_KEY must be in environment");
        let key_id: String = std::env::var("KEY_ID").expect("KEY_ID must be in environment");
        let region = std::env::var("REGION").expect("REGION must be in environment");
        let signer = AWSSigner::new(1, access_key, secret_access_key, key_id, region)
            .await
            .unwrap();

        let message = "Hello World";
        let sig = signer.sign_message(message).await.unwrap();
        let recovred_address = sig.recover(message).unwrap();
        assert_eq!(recovred_address, signer.address);
    }
    #[tokio::test]
    async fn test_sign_typed_transaction() {
        let access_key = std::env::var("ACCESS_KEY").expect("ACCESS_KEY must be in environment");
        let secret_access_key =
            std::env::var("SECRET_ACCESS_KEY").expect("SECRET_ACCESS_KEY must be in environment");
        let key_id: String = std::env::var("KEY_ID").expect("KEY_ID must be in environment");
        let region = std::env::var("REGION").expect("REGION must be in environment");
        let signer = AWSSigner::new(1, access_key, secret_access_key, key_id, region)
            .await
            .unwrap();

        let tx = &ethers::types::transaction::eip2718::TypedTransaction::Eip1559(
            Eip1559TransactionRequest::new()
                .to("vitalik.eth")
                .value(parse_units(1, 18).unwrap())
                .nonce(1)
                .gas(21000)
                .max_priority_fee_per_gas(U256::from(1000000000))
                .chain_id(signer.chain_id),
        );
        let signature = signer.sign_transaction(tx).await.unwrap();
        assert_ne!(signature.v, 27);
        assert_ne!(signature.v, 28);
        let recovered_address = signature.recover(tx.sighash()).unwrap();
        assert_eq!(signer.address(), recovered_address);
    }
}
