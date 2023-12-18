pub mod aws_signer_error;

use std::ops::{Div, Sub};

use async_trait::async_trait;
use aws_config::{BehaviorVersion, Region};
use aws_sdk_kms::{config::Credentials, primitives::Blob, Client};
use ethers::{
    core::k256::{
        elliptic_curve::{generic_array::GenericArray, PrimeField},
        Scalar,
    },
    signers::Signer,
    types::{
        transaction::{eip2718::TypedTransaction, eip712::Eip712},
        Address, RecoveryMessage, Signature, H256, U256,
    },
    utils::{hash_message, keccak256},
};

use self::aws_signer_error::AWSSignerError;
use rasn_pkix::SubjectPublicKeyInfo;

/**
 * The maximum N value of the SECP256K1 curve
 */
const SECP256K1_N: U256 = U256([
    0xffffffffffffffff,
    0xfffffffffffffffe,
    0xbaaedce6af48a03b,
    0xbfd25e8cd0364141,
]);

#[derive(Clone, Debug)]
pub struct AWSSigner {
    pub client: Client,
    pub key_id: String,
    pub address: Address,
    pub chain_id: u64,
}

impl AWSSigner {
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
        Ok(Self {
            client,
            address,
            key_id,
            chain_id,
        })
    }

    pub async fn sign_hash(&self, hash: H256) -> Result<Signature, AWSSignerError> {
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
}

pub async fn get_ethereum_address(
    client: &Client,
    key_id: &str,
) -> Result<Address, AWSSignerError> {
    let public_key_der = client
        .get_public_key()
        .key_id(key_id)
        .send()
        .await
        .map_err(|e| AWSSignerError::SdkError(format!("{:?}", e)))?
        .public_key
        .ok_or(AWSSignerError::MissingPublicKey)?;
    let decoded_public_key_info = decode_subject_public_key_info(&public_key_der.into_inner())?;
    let decded_public_key_stream = decoded_public_key_info
        .subject_public_key
        .to_bitvec()
        .into_vec();
    compute_ethereum_address_from_decoded_der(&decded_public_key_stream)
}

fn compute_ethereum_address_from_decoded_der(
    decoded_public_key: &Vec<u8>,
) -> Result<Address, AWSSignerError> {
    //First byte should be 0x04 and it should be remove
    let first_byte = decoded_public_key[0];
    if first_byte != 0x04 {
        return Err(AWSSignerError::ComputeEthereumAddressError(
            "Malformed decoded DER public key. First byte not 0x04".to_owned(),
        ));
    };
    let cleaned = &decoded_public_key[1..];
    let last_20_bytes_hashed = &keccak256(cleaned)[12..];
    Ok(Address::from_slice(last_20_bytes_hashed))
}

fn decode_subject_public_key_info(
    der_encoded: &[u8],
) -> Result<SubjectPublicKeyInfo, aws_signer_error::AWSSignerError> {
    rasn::der::decode::<SubjectPublicKeyInfo>(der_encoded)
        .map_err(|e| AWSSignerError::RasnError(format!("{:?}", e)))
}

fn decode_der_signature(signature: &[u8]) -> Result<Signature, AWSSignerError> {
    // https://crypto.stackexchange.com/questions/1795/how-can-i-convert-a-der-ecdsa-signature-to-asn-1
    // 0x30 b1 0x02 b2 (vr) 0x02 b3 (vs)
    let r_len: usize = signature[3] as usize;
    let r_start_index = 4 as usize;
    let r_final_index = r_start_index + r_len;

    let s_len = signature[r_final_index as usize + 1] as usize;
    let s_start_index = r_final_index + 2;
    let s_last_index = s_start_index + s_len;

    let r = &signature[match r_len == 33 {
        true => r_start_index + 1,
        false => r_start_index,
    }..r_final_index];

    let s = &signature[match s_len == 33 {
        true => s_start_index + 1,
        false => s_start_index,
    }..s_last_index];
    Ok(Signature {
        r: U256::from_big_endian(r),
        s: U256::from_big_endian(s),
        v: 27,
    })
}

/**
 * This function creates the appropraite eth signature from the ecdsa signature.
 * This function checks that the S value from the ecdsa signature is smaller than half of the SECP256K1 curve N value, as defined in EIP-2
 * If the provided S value in ecsdsa_signature is larger than half the SECP256K1 N value, a new S' value is computed where S' = (N - S)
 * If the provided S value is larger than the SECP256K1 N value, we have to negate the scalar by the order of the curve.
 * The V value is set to 27 by default, and thus might be invalid.
 */
fn correct_s_for_malleability(signature: Signature) -> Result<Signature, AWSSignerError> {
    let half_n: U256 = SECP256K1_N.div(U256::from(2));
    let mut new_signature = signature;
    if signature.s.gt(&SECP256K1_N) {
        //Normalize
        //https://ethereum.stackexchange.com/questions/65893/what-should-we-do-if-s-in-the-ecdsa-signature-is-greater-than-n-2
        let mut bytes = [0u8; 32];
        signature.s.to_big_endian(&mut bytes);
        let scalar_option = Scalar::from_repr(GenericArray::clone_from_slice(&bytes));
        let scalar = match scalar_option.is_some().unwrap_u8() == 1 {
            true => scalar_option.unwrap(),
            false => return Err(AWSSignerError::NormalizeFailure),
        };
        new_signature.s = U256::from_big_endian(&scalar.to_bytes());
    } else if signature.s.gt(&half_n) && signature.s.lt(&SECP256K1_N) {
        new_signature.s = SECP256K1_N.sub(signature.s);
    }
    Ok(new_signature)
}
// 0xeb74b685a3900eae809230b9bcffa430016f64b4
/**
 * This function checks if the default v value (27) is valid.
 * Using the signature and message, the ethereum address is recovered. If the ethereum address recovered is different from the signer's address, a value of 28 is used.
 */
fn correct_eth_sig_r_value<S: Send + Sync + Into<RecoveryMessage>>(
    signature: Signature,
    message: S,
    signer_address: Address,
) -> Result<Signature, AWSSignerError> {
    let mut new_singature = signature;
    let recovered_address = signature
        .recover(message)
        .map_err(|err| AWSSignerError::SignatureError(err))?;
    if recovered_address != signer_address {
        new_singature.v = 28
    }
    Ok(new_singature)
}

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
            client: self.client,
            key_id: self.key_id,
            address: self.address,
            chain_id: chain_id.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use ethers::{
        signers::Signer,
        types::{Address, Signature, U256},
        utils::{hash_message, keccak256},
    };

    use super::{
        compute_ethereum_address_from_decoded_der, correct_eth_sig_r_value,
        correct_s_for_malleability, AWSSigner,
    };

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
    #[test]
    fn test_create_eth_sig_from_ecdsa() {
        let signer = "0x174938e1c772366a8c7a76e9fb32e8fb79a43c0f"
            .parse::<Address>()
            .unwrap();
        let message = "hello World!";
        let message_hash = keccak256(message);
        let eth_signature = Signature {
            r: U256::from_str_radix(
                "32545751729199740260568142112760402418613920763767693241849496416066142917742",
                10,
            )
            .unwrap(),
            s: U256::from_str_radix(
                "20841215707394945395928405730442194368774188573588963931659264645900649255855",
                10,
            )
            .unwrap(),
            v: 27,
        };
        let eth_signature = correct_s_for_malleability(eth_signature).unwrap();
        let eth_signature = correct_eth_sig_r_value(eth_signature, message_hash, signer).unwrap();
        let recovered_address = eth_signature.recover(message_hash).unwrap();
        assert_eq!(signer, recovered_address);
    }

    #[test]
    fn test_compute_ethereum_address() {
        let decoded_der = hex::decode("043d471f65fb7066ef3656c90fc262d14fecd637adb5d1a369427ebb342340badd791ec332ee985b7ec5af6d8ee83e1237342805c219de34fa2b42e753358cd3f5").unwrap();
        let expected_address = "0x3b62a92b8873a89d8c1e487fe8258f0360a97037"
            .parse::<Address>()
            .unwrap();
        let computed_ethereum_address =
            compute_ethereum_address_from_decoded_der(&decoded_der).unwrap();

        assert_eq!(expected_address, computed_ethereum_address);
    }
}
