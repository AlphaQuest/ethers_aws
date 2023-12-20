# AWSSigner

ether_aws is a wrapper around the aws sdk that allows using AWS KMS as a signer, `AWSSigner`
`AWSSigner` fully implements the `Signer` trait from ether-rs. 

# Quickstart
Add this to your Cargo.toml:
```
[dependencies]
ethers_aws = "0.1"
```
# Usage
```
//Set up all credentials
let access_key = std::env::var("ACCESS_KEY").expect("ACCESS_KEY must be in environment");
let secret_access_key = std::env::var("SECRET_ACCESS_KEY").expect("SECRET_ACCESS_KEY must be in environment");
let key_id: String = std::env::var("KEY_ID").expect("KEY_ID must be in environment");
let region = std::env::var("REGION").expect("REGION must be in environment");
//Create the signer
let aws_signer = AWSSigner::new(
        ethers::types::Chain::Mainnet as u64,
        access_key,
        secret_access_key,
        key_id,
        region,
    )
    .await
    .expect("Cannot create AWS signer");
let provider = Provider::<Http>::try_from(anvil.endpoint()).unwrap();
let signer_middleware = SignerMiddleware::new(provider, aws_signer);

//Create transaction as usual
let one_ether: U256 = parse_units(1, 18 as i32).unwrap().into();
let tx_request = Eip1559TransactionRequest::new().to(Address::zero())
        .value(one_ether);
let response = signer_middleware.send_transaction(tx_request, None)

```

# AWS setup (Optional)
## Create an IAM user
An AWS IAM user must be created with the appropriate permissions. During the creation process add these policies for the to be created IAM user.
```
AWSKeyManagementServicePowerUser
ROSAKMSProviderPolicy
```
Once created, go to the newly created user and add an access_key to it. Chose `Application running outside AWS`. Save the `access_key` and the `secret_access_key`
## Create a new public private key pair
Go to the AWKS KMS page and follow these steps:
1) Choose `Create a key`
2) Choose `Asymmetric` for `Key Type`
3) Choose `Sign and Verify` for `Key Usage`
4) Choose `ECC_SECG_P256K1` for `Key spec`
5) Click next and add tags
6) Click next and in the `Key administrators` choose the user created in the `Create an IAM user` section
7) Click next and in `Key User` choose the user created in `Create an IAM user` section
8) Once the key is created, get the `key_id`

Install this library into your rust project
```
cargo add ethers_aws
```



# Example
```
use ethers_aws::AWSSigner
let aws_signer = AWSSigner::new();
```