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