use reqwest::Method;

use crate::error::Error;
use crate::evm::paths;
use crate::transport::transport::Transport;

use super::{
    CreateSignerRequest, CreateSignerResponse, GrantAccessRequest, ListSignersFilter,
    ListSignersResponse, LockSignerResponse, SignerAccessEntry, TransferOwnershipRequest,
    UnlockSignerRequest, UnlockSignerResponse,
};

#[derive(Clone)]
pub struct SignerService {
    transport: Transport,
}

impl SignerService {
    pub fn new(transport: Transport) -> Self {
        Self { transport }
    }

    pub fn list(&self, filter: Option<&ListSignersFilter>) -> Result<ListSignersResponse, Error> {
        self.transport.request_json(
            Method::GET,
            &paths::signers_list(filter),
            Option::<&()>::None,
            Some(&[200]),
        )
    }

    pub fn create(&self, req: &CreateSignerRequest) -> Result<CreateSignerResponse, Error> {
        self.transport
            .request_json(Method::POST, paths::SIGNERS, Some(req), Some(&[200, 201]))
    }

    pub fn unlock(
        &self,
        address: &str,
        req: &UnlockSignerRequest,
    ) -> Result<UnlockSignerResponse, Error> {
        self.transport.request_json(
            Method::POST,
            &paths::signer_unlock(address),
            Some(req),
            Some(&[200]),
        )
    }

    pub fn lock(&self, address: &str) -> Result<LockSignerResponse, Error> {
        self.transport.request_json(
            Method::POST,
            &paths::signer_lock(address),
            Option::<&()>::None,
            Some(&[200]),
        )
    }

    pub fn approve_signer(&self, address: &str) -> Result<(), Error> {
        self.transport.request_raw(
            Method::POST,
            &paths::signer_approve(address),
            Option::<&()>::None,
            Some(&[200]),
        )?;
        Ok(())
    }

    pub fn transfer_ownership(
        &self,
        address: &str,
        req: &TransferOwnershipRequest,
    ) -> Result<(), Error> {
        self.transport.request_raw(
            Method::POST,
            &paths::signer_transfer(address),
            Some(req),
            Some(&[200]),
        )?;
        Ok(())
    }

    pub fn delete_signer(&self, address: &str) -> Result<(), Error> {
        self.transport.request_raw(
            Method::DELETE,
            &paths::signer(address),
            Option::<&()>::None,
            Some(&[204]),
        )?;
        Ok(())
    }

    pub fn grant_access(&self, address: &str, req: &GrantAccessRequest) -> Result<(), Error> {
        self.transport.request_raw(
            Method::POST,
            &paths::signer_access(address),
            Some(req),
            Some(&[200]),
        )?;
        Ok(())
    }

    pub fn revoke_access(&self, address: &str, api_key_id: &str) -> Result<(), Error> {
        self.transport.request_raw(
            Method::DELETE,
            &paths::signer_access_entry(address, api_key_id),
            Option::<&()>::None,
            Some(&[200]),
        )?;
        Ok(())
    }

    pub fn list_access(&self, address: &str) -> Result<Vec<SignerAccessEntry>, Error> {
        self.transport.request_json(
            Method::GET,
            &paths::signer_access(address),
            Option::<&()>::None,
            Some(&[200]),
        )
    }
}

#[cfg(feature = "async")]
mod asynchronous {
    use super::*;
    use crate::transport::async_transport::AsyncTransport;

    /// Non-blocking counterpart of [`SignerService`].
    #[derive(Clone)]
    pub struct AsyncSignerService {
        transport: AsyncTransport,
    }

    impl AsyncSignerService {
        pub fn new(transport: AsyncTransport) -> Self {
            Self { transport }
        }

        pub async fn list(
            &self,
            filter: Option<&ListSignersFilter>,
        ) -> Result<ListSignersResponse, Error> {
            self.transport
                .request_json(
                    Method::GET,
                    &paths::signers_list(filter),
                    Option::<&()>::None,
                    Some(&[200]),
                )
                .await
        }

        pub async fn create(
            &self,
            req: &CreateSignerRequest,
        ) -> Result<CreateSignerResponse, Error> {
            self.transport
                .request_json(Method::POST, paths::SIGNERS, Some(req), Some(&[200, 201]))
                .await
        }

        pub async fn unlock(
            &self,
            address: &str,
            req: &UnlockSignerRequest,
        ) -> Result<UnlockSignerResponse, Error> {
            self.transport
                .request_json(
                    Method::POST,
                    &paths::signer_unlock(address),
                    Some(req),
                    Some(&[200]),
                )
                .await
        }

        pub async fn lock(&self, address: &str) -> Result<LockSignerResponse, Error> {
            self.transport
                .request_json(
                    Method::POST,
                    &paths::signer_lock(address),
                    Option::<&()>::None,
                    Some(&[200]),
                )
                .await
        }

        pub async fn approve_signer(&self, address: &str) -> Result<(), Error> {
            self.transport
                .request_raw(
                    Method::POST,
                    &paths::signer_approve(address),
                    Option::<&()>::None,
                    Some(&[200]),
                )
                .await?;
            Ok(())
        }

        pub async fn transfer_ownership(
            &self,
            address: &str,
            req: &TransferOwnershipRequest,
        ) -> Result<(), Error> {
            self.transport
                .request_raw(
                    Method::POST,
                    &paths::signer_transfer(address),
                    Some(req),
                    Some(&[200]),
                )
                .await?;
            Ok(())
        }

        pub async fn delete_signer(&self, address: &str) -> Result<(), Error> {
            self.transport
                .request_raw(
                    Method::DELETE,
                    &paths::signer(address),
                    Option::<&()>::None,
                    Some(&[204]),
                )
                .await?;
            Ok(())
        }

        pub async fn grant_access(
            &self,
            address: &str,
            req: &GrantAccessRequest,
        ) -> Result<(), Error> {
            self.transport
                .request_raw(
                    Method::POST,
                    &paths::signer_access(address),
                    Some(req),
                    Some(&[200]),
                )
                .await?;
            Ok(())
        }

        pub async fn revoke_access(&self, address: &str, api_key_id: &str) -> Result<(), Error> {
            self.transport
                .request_raw(
                    Method::DELETE,
                    &paths::signer_access_entry(address, api_key_id),
                    Option::<&()>::None,
                    Some(&[200]),
                )
                .await?;
            Ok(())
        }

        pub async fn list_access(&self, address: &str) -> Result<Vec<SignerAccessEntry>, Error> {
            self.transport
                .request_json(
                    Method::GET,
                    &paths::signer_access(address),
                    Option::<&()>::None,
                    Some(&[200]),
                )
                .await
        }
    }
}

#[cfg(feature = "async")]
pub use asynchronous::AsyncSignerService;
