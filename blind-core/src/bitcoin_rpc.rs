use serde::Deserialize;

pub struct Client {
    base_url: String,
}

impl Client {
    pub fn new(base_url: &str) -> Client {
        Client {
            base_url: base_url.to_owned()
        }
    }

    #[inline]
    pub fn get_wallet_url(&self, name: &str) -> String {
        format!("{}/wallet/{}", &self.base_url, name)
    }

    pub fn create_wallet(&self, name: &str) -> anyhow::Result<Wallet> {
        let _ = execute_rpc::<ureq::serde_json::Value>(
            &self.base_url,
            ureq::json!({"jsonrpc": "1.0", "method": "createwallet", "params": [name]})
        )?;
        Ok(Wallet{
            url: self.get_wallet_url(name)
        })
    }

    pub fn create_raw_transaction(&self, address: &str, amount: &bitcoin::Amount) -> anyhow::Result<String> {
        execute_rpc::<String>(
            &self.base_url,
            ureq::json!({"jsonrpc": "1.0", "method": "createrawtransaction", "params": [[], { address:amount.as_btc() }] })
        )
    }

    pub fn mine(&self, num: u64, address: &str) -> anyhow::Result<Vec::<String>> {
        execute_rpc::<Vec::<String>>(
            &self.base_url,
            ureq::json!({"jsonrpc": "1.0", "method": "generatetoaddress", "params": [num, address] })
        )
    }

    pub fn send_raw_transaction(&self, raw_transaction: &str) -> anyhow::Result<ureq::serde_json::Value>{
        execute_rpc::<ureq::serde_json::Value>(
            &self.base_url,
            ureq::json!({"jsonrpc": "1.0", "method": "sendrawtransaction", "params": [raw_transaction] }),
        )
    }

    pub fn get_raw_transaction(&self, txid: &str) -> anyhow::Result<String> {
        execute_rpc::<String>(
            &self.base_url,
            ureq::json!({"jsonrpc": "1.0", "method": "getrawtransaction", "params": [txid] })
        )
    }
}

pub struct Wallet {
    url: String
}

impl Wallet {
    pub fn get_new_address(&self) -> anyhow::Result<String> {
        execute_rpc::<String>(
            &self.url,
            ureq::json!({"jsonrpc": "1.0", "method": "getnewaddress", "params": ["", "bech32"] })
        )
    }

    pub fn get_balance(&self) -> anyhow::Result<bitcoin::Amount> {
        let balance = execute_rpc::<f64>(
            &self.url,
            ureq::json!({"jsonrpc": "1.0", "method": "getbalance", "params": [] })
        )?;
        let amount = bitcoin::Amount::from_btc(balance)?;

        Ok(amount)
    }

    pub fn funding_raw_transaction(&self, hex: &str) -> anyhow::Result<FundRawTransactionResponse> {
        execute_rpc::<FundRawTransactionResponse>(
            &self.url,
            ureq::json!({"jsonrpc": "1.0", "method": "fundrawtransaction", "params": [hex] })
        )
    }

    pub fn sign_raw_transaction(&self, hex: &str) -> anyhow::Result<String> {
        let response = execute_rpc::<SignRawTransactionResponse>(
            &self.url,
            ureq::json!({"jsonrpc": "1.0", "method": "signrawtransactionwithwallet", "params": [hex] })
        )?;
        Ok(response.hex)
    }
}

fn execute_rpc<T: serde::de::DeserializeOwned>(url: &str, data: ureq::serde_json::Value) -> anyhow::Result<T> {
    let result = ureq::post(url).send_json(data);
    match result {
        Ok(response) | Err(ureq::Error::Status(_, response)) => {
            match response.into_json::<RpcResult::<T>>()? {
                RpcResult { result: Some(data), .. } => Ok(data),
                RpcResult { error: Some(error), .. } => Err(error.into()),
                _ => Err(anyhow::anyhow!("invalid rpc response"))
            }
        },
        Err(e) => Err(e.into())
    }
}

#[derive(Deserialize)]
struct RpcResult<T> {
    result: Option<T>,
    error: Option<RpcError>
}

#[derive(Debug, Deserialize, thiserror::Error)]
#[error("[code: {code}] {message}")]
struct RpcError{
    code: i32,
    message: String
}

#[derive(Deserialize)]
pub struct FundRawTransactionResponse {
    pub hex: String,
    pub changepos: i8,
    pub fee: f64,
}

#[derive(Deserialize)]
pub struct SignRawTransactionResponse {
    pub hex: String,
}