use reqwest::Method;

use crate::error::Error;
use crate::evm::paths;
use crate::transport::transport::Transport;

use super::{
    CreateHdWalletRequest, DeriveAddressRequest, DeriveAddressResponse, HdWalletResponse,
    ListDerivedAddressesResponse, ListHdWalletsResponse,
};

/// `action` defaults to `create`; `import` is set explicitly by the caller.
fn with_default_action(mut req: CreateHdWalletRequest) -> CreateHdWalletRequest {
    if req.action.is_empty() {
        req.action = "create".to_string();
    }
    req
}

#[derive(Clone)]
pub struct HdWalletService {
    transport: Transport,
}

impl HdWalletService {
    pub fn new(transport: Transport) -> Self {
        Self { transport }
    }

    pub fn create(&self, req: CreateHdWalletRequest) -> Result<HdWalletResponse, Error> {
        let req = with_default_action(req);
        self.transport
            .request_json(Method::POST, paths::HD_WALLETS, Some(&req), Some(&[201]))
    }

    pub fn import(&self, mut req: CreateHdWalletRequest) -> Result<HdWalletResponse, Error> {
        req.action = "import".to_string();
        self.create(req)
    }

    pub fn list(&self) -> Result<ListHdWalletsResponse, Error> {
        self.transport.request_json(
            Method::GET,
            paths::HD_WALLETS,
            Option::<&()>::None,
            Some(&[200]),
        )
    }

    pub fn derive_address(
        &self,
        primary_addr: &str,
        req: &DeriveAddressRequest,
    ) -> Result<DeriveAddressResponse, Error> {
        self.transport.request_json(
            Method::POST,
            &paths::hd_wallet_derive(primary_addr),
            Some(req),
            Some(&[200]),
        )
    }

    pub fn list_derived(
        &self,
        primary_addr: &str,
    ) -> Result<ListDerivedAddressesResponse, Error> {
        self.transport.request_json(
            Method::GET,
            &paths::hd_wallet_derived(primary_addr),
            Option::<&()>::None,
            Some(&[200]),
        )
    }
}

#[cfg(feature = "async")]
mod asynchronous {
    use super::*;
    use crate::transport::async_transport::AsyncTransport;

    /// Non-blocking counterpart of [`HdWalletService`].
    #[derive(Clone)]
    pub struct AsyncHdWalletService {
        transport: AsyncTransport,
    }

    impl AsyncHdWalletService {
        pub fn new(transport: AsyncTransport) -> Self {
            Self { transport }
        }

        pub async fn create(
            &self,
            req: CreateHdWalletRequest,
        ) -> Result<HdWalletResponse, Error> {
            let req = with_default_action(req);
            self.transport
                .request_json(Method::POST, paths::HD_WALLETS, Some(&req), Some(&[201]))
                .await
        }

        pub async fn import(
            &self,
            mut req: CreateHdWalletRequest,
        ) -> Result<HdWalletResponse, Error> {
            req.action = "import".to_string();
            self.create(req).await
        }

        pub async fn list(&self) -> Result<ListHdWalletsResponse, Error> {
            self.transport
                .request_json(
                    Method::GET,
                    paths::HD_WALLETS,
                    Option::<&()>::None,
                    Some(&[200]),
                )
                .await
        }

        pub async fn derive_address(
            &self,
            primary_addr: &str,
            req: &DeriveAddressRequest,
        ) -> Result<DeriveAddressResponse, Error> {
            self.transport
                .request_json(
                    Method::POST,
                    &paths::hd_wallet_derive(primary_addr),
                    Some(req),
                    Some(&[200]),
                )
                .await
        }

        pub async fn list_derived(
            &self,
            primary_addr: &str,
        ) -> Result<ListDerivedAddressesResponse, Error> {
            self.transport
                .request_json(
                    Method::GET,
                    &paths::hd_wallet_derived(primary_addr),
                    Option::<&()>::None,
                    Some(&[200]),
                )
                .await
        }
    }
}

#[cfg(feature = "async")]
pub use asynchronous::AsyncHdWalletService;
