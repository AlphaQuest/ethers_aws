use ethers::{
    middleware::{Middleware, SignerMiddleware},
    providers::{Http, Provider},
    signers::LocalWallet,
    types::{Address, Eip1559TransactionRequest, TransactionRequest, U256},
    utils::{parse_units, Anvil, AnvilInstance},
};
use ethers_aws::aws_signer::AWSSigner;

#[tokio::main]
async fn main() {
    let anvil = setup_anvil();
    let access_key = std::env::var("ACCESS_KEY").expect("ACCESS_KEY must be in environment");
    let secret_access_key =
        std::env::var("SECRET_ACCESS_KEY").expect("SECRET_ACCESS_KEY must be in environment");
    let key_id: String = std::env::var("KEY_ID").expect("KEY_ID must be in environment");
    let region = std::env::var("REGION").expect("REGION must be in environment");
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

    let _anvil = add_eth_to_aws_address(anvil, signer_middleware.address()).await;
    let one_ether: U256 = parse_units(1, 18 as i32).unwrap().into();
    let tx_request = Eip1559TransactionRequest::new()
        .to(Address::zero())
        .value(one_ether);
    let tx_hash = signer_middleware
        .send_transaction(tx_request, None)
        .await
        .unwrap()
        .await
        .unwrap()
        .unwrap()
        .transaction_hash;
    println!(
        "Succesfuly sent 1 ether to vitalik from aws account at tx_hash {:?}",
        tx_hash
    );
}

async fn add_eth_to_aws_address(anvil: AnvilInstance, aws_address: Address) -> AnvilInstance {
    let dev_wallet_private_key =
        "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
            .parse::<LocalWallet>()
            .unwrap();
    let provider = Provider::<Http>::try_from(anvil.endpoint()).unwrap();
    let signer_middleware = SignerMiddleware::new(provider, dev_wallet_private_key);

    let ten_ether: U256 = parse_units(10, 18 as i32).unwrap().into();
    let tx_request = Eip1559TransactionRequest::new()
        .to(aws_address)
        .value(ten_ether);
    let result = signer_middleware
        .send_transaction(tx_request, None)
        .await
        .unwrap()
        .await
        .unwrap()
        .unwrap()
        .transaction_hash;
    println!(
        "Succesfully provided 10 ether to aws account. Hash {:?}",
        result
    );
    anvil
}

fn setup_anvil() -> AnvilInstance {
    //Setup anvil with the same chain id
    let anvil = Anvil::new()
        .fork("https://1rpc.io/eth")
        .arg("--balance=100000")
        .arg("--chain-id=1")
        .spawn();
    anvil
}
