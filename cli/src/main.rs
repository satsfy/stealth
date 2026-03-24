use std::env;

use corepc_node::anyhow;
use corepc_node::client::bitcoin::Amount;
use corepc_node::{AddressType, Client, Node};

type Result<T> = anyhow::Result<T>;

pub fn init_bitcoind() -> Result<Node> {
    let bitcoind_exe = corepc_node::exe_path()?;
    let conf = corepc_node::Conf::default();
    let bitcoind = corepc_node::Node::with_conf(bitcoind_exe, &conf)?;
    Ok(bitcoind)
}

fn create_and_fund_wallets(
    bitcoind: &Node,
    wallets: Vec<(&str, Option<AddressType>)>,
) -> Result<Vec<Client>> {
    let mut funded_wallets = Vec::with_capacity(wallets.len());
    let funding_wallet = bitcoind.create_wallet("funding_wallet")?;
    let funding_address = funding_wallet.new_address()?;

    // Mine enough coinbase outputs to make funds spendable.
    bitcoind
        .client
        .generate_to_address(101 + wallets.len(), &funding_address)?;

    for (wallet_name, address_type) in wallets {
        let wallet = bitcoind.create_wallet(wallet_name)?;
        let address = match address_type {
            Some(address_type) => wallet.new_address_with_type(address_type)?,
            None => wallet.new_address()?,
        };
        funding_wallet.send_to_address(&address, Amount::from_btc(50.0)?)?;
        funded_wallets.push(wallet);
    }

    // Confirm funding transactions.
    bitcoind.client.generate_to_address(1, &funding_address)?;

    for wallet in &funded_wallets {
        let balances = wallet.get_balances()?.into_model()?;
        anyhow::ensure!(
            balances.mine.trusted == Amount::from_btc(50.0)?,
            "wallet doesn't have expected amount of bitcoin"
        );
    }

    Ok(funded_wallets)
}

pub fn init_bitcoind_sender_receiver(
    sender_address_type: Option<AddressType>,
    receiver_address_type: Option<AddressType>,
) -> Result<(Node, Client, Client)> {
    let bitcoind = init_bitcoind()?;
    let mut wallets = create_and_fund_wallets(
        &bitcoind,
        vec![
            ("sender", sender_address_type),
            ("receiver", receiver_address_type),
        ],
    )?;

    let sender = wallets.remove(0);
    let receiver = wallets.remove(0);

    Ok((bitcoind, sender, receiver))
}

fn parse_rpc_arg(raw: &str) -> serde_json::Value {
    serde_json::from_str(raw).unwrap_or_else(|_| serde_json::Value::String(raw.to_owned()))
}

fn call_bitcoin_cli_like(method: &str, args: &[serde_json::Value]) -> Result<serde_json::Value> {
    // Starts a regtest node and executes one RPC command, similar to `bitcoin-cli <method> ...`.
    let bitcoind = init_bitcoind()?;
    let response = bitcoind.client.call::<serde_json::Value>(method, args)?;
    Ok(response)
}

fn demo_send() -> Result<()> {
    let (_bitcoind, sender, receiver) =
        init_bitcoind_sender_receiver(Some(AddressType::Legacy), Some(AddressType::Legacy))?;

    let receiver_address = receiver.new_address()?;
    let txid = sender
        .send_to_address(&receiver_address, Amount::from_btc(1.0)?)?
        .into_model()?
        .txid;

    println!("{txid}");
    Ok(())
}

fn run() -> Result<()> {
    let args: Vec<String> = env::args().skip(1).collect();

    if args.is_empty() {
        print_usage();
        return Ok(());
    }

    if args[0] == "demo" {
        return demo_send();
    }

    let method = &args[0];
    let rpc_args: Vec<serde_json::Value> = args[1..].iter().map(|arg| parse_rpc_arg(arg)).collect();
    let response = call_bitcoin_cli_like(method, &rpc_args)?;
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

fn print_usage() {
    eprintln!("Usage:");
    eprintln!("  stealth-cli demo");
    eprintln!("  stealth-cli <rpc_method> [rpc_arg1 ... rpc_argN]");
    eprintln!();
    eprintln!("Examples:");
    eprintln!("  stealth-cli getblockchaininfo");
    eprintln!("  stealth-cli getnewaddress \"\" bech32");
    eprintln!("  stealth-cli getblockcount");
}

fn main() {
    if let Err(err) = run() {
        eprintln!("error: {err:#}");
        std::process::exit(1);
    }
}
