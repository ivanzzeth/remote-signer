use reqwest::Method;

use crate::error::Error;
use crate::transport::transport::Transport;

use super::{CreateHdWalletRequest, DeriveAddressRequest, DeriveAddressResponse, HdWalletResponse, ListDerivedAddressesResponse, ListHdWalletsResponse};

#[derive(Clone)]
pub struct HdWalletService {
    transport: Transport,
}

impl HdWalletService {
    pub fn new(transport: Transport) -> Self {
        Self { transport }
    }

    pub fn create(&self, mut req: CreateHdWalletRequest) -> Result<HdWalletResponse, Error> {
        if req.action.is_empty() {
            req.action = "create".to_string();
        }
        self.transport
            .request_json(Method::POST, "/api/v1/evm/hd-wallets", Some(&req), Some(&[201]))
    }

    pub fn import(&self, mut req: CreateHdWalletRequest) -> Result<HdWalletResponse, Error> {
        req.action = "import".to_string();
        self.create(req)
    }

    pub fn list(&self) -> Result<ListHdWalletsResponse, Error> {
        self.transport
            .request_json(Method::GET, "/api/v1/evm/hd-wallets", Option::<&()>::None, Some(&[200]))
    }

    pub fn derive_address(&self, primary_addr: &str, req: &DeriveAddressRequest) -> Result<DeriveAddressResponse, Error> {
        let path = format!("/api/v1/evm/hd-wallets/{}/derive", urlencoding::encode(primary_addr));
        self.transport
            .request_json(Method::POST, &path, Some(req), Some(&[200]))
    }

    pub fn list_derived(&self, primary_addr: &str) -> Result<ListDerivedAddressesResponse, Error> {
        let path = format!("/api/v1/evm/hd-wallets/{}/derived", urlencoding::encode(primary_addr));
        self.transport
            .request_json(Method::GET, &path, Option::<&()>::None, Some(&[200]))
    }
}
