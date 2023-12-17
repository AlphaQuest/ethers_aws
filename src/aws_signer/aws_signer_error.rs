use aws_sdk_kms::error::SdkError;
use ethers::types::SignatureError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AWSSignerError {
    #[error("SdkError Error. Error = `{0}`")]
    SdkError(String),
    #[error("X509 Error. Error = `{0}`")]
    X509Error(String),
    #[error("Cannot get public key")]
    MissingPublicKey,
    #[error("ASN1 error = `{0}`")]
    RasnError(String),
    #[error("Compute ethereum address error = `{0}`")]
    ComputeEthereumAddressError(String),
    #[error("Cannot get the R value")]
    CannotGetRValue,
    #[error("Signature error error = `{0}`")]
    SignatureError(SignatureError),
    #[error("Failed to normalize generated S")]
    NormalizeFailure,
}
