use thiserror::Error;

#[derive(Error, Clone, Debug)]
pub enum AWSSignerError {
    #[error("RPC Error. Error = `{0}`")]
    RPCError(String),
}
