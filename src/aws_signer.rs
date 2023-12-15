pub mod aws_signer_error;

use async_trait::async_trait;
use ethers::{
    signers::Signer,
    types::{
        transaction::{eip2718::TypedTransaction, eip712::Eip712},
        Address, Signature,
    },
};

use self::aws_signer_error::AWSSignerError;

#[derive(Clone, Copy, Debug)]
pub struct AWSSigner {
    pub address: Address,
    pub chain_id: u64,
}

impl AWSSigner {}

#[async_trait]
impl Signer for AWSSigner {
    type Error = AWSSignerError;
    async fn sign_transaction(&self, message: &TypedTransaction) -> Result<Signature, Self::Error> {
        todo!()
    }
    async fn sign_message<S: Send + Sync + AsRef<[u8]>>(
        &self,
        message: S,
    ) -> Result<Signature, Self::Error> {
        todo!()
    }

    /// Encodes and signs the typed data according EIP-712.
    /// Payload must implement Eip712 trait.
    async fn sign_typed_data<T: Eip712 + Send + Sync>(
        &self,
        payload: &T,
    ) -> Result<Signature, Self::Error> {
        todo!()
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
            address: self.address,
            chain_id: chain_id.into(),
        }
    }
}
