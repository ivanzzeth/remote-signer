use reqwest::Method;

use crate::error::Error;
use crate::transport::transport::Transport;

use super::{CreateSignerRequest, CreateSignerResponse, GrantAccessRequest, ListSignersFilter, ListSignersResponse, LockSignerResponse, SignerAccessEntry, TransferOwnershipRequest, UnlockSignerRequest, UnlockSignerResponse};

#[derive(Clone)]
pub struct SignerService {
    transport: Transport,
}

impl SignerService {
    pub fn new(transport: Transport) -> Self {
        Self { transport }
    }

    pub fn list(&self, filter: Option<&ListSignersFilter>) -> Result<ListSignersResponse, Error> {
        let mut path = String::from("/api/v1/evm/signers");
        let mut params = vec![];
        if let Some(f) = filter {
            if let Some(v) = &f.signer_type {
                params.push(format!("type={}", urlencoding::encode(v)));
            }
            if let Some(v) = f.limit {
                params.push(format!("limit={}", v));
            }
            if let Some(v) = f.offset {
                params.push(format!("offset={}", v));
            }
        }
        if !params.is_empty() {
            path.push('?');
            path.push_str(&params.join("&"));
        }

        self.transport
            .request_json(Method::GET, &path, Option::<&()>::None, Some(&[200]))
    }

    pub fn create(&self, req: &CreateSignerRequest) -> Result<CreateSignerResponse, Error> {
        self.transport
            .request_json(Method::POST, "/api/v1/evm/signers", Some(req), Some(&[200, 201]))
    }

    pub fn unlock(&self, address: &str, req: &UnlockSignerRequest) -> Result<UnlockSignerResponse, Error> {
        let path = format!("/api/v1/evm/signers/{}/unlock", urlencoding::encode(address));
        self.transport
            .request_json(Method::POST, &path, Some(req), Some(&[200]))
    }

    pub fn lock(&self, address: &str) -> Result<LockSignerResponse, Error> {
        let path = format!("/api/v1/evm/signers/{}/lock", urlencoding::encode(address));
        self.transport
            .request_json(Method::POST, &path, Option::<&()>::None, Some(&[200]))
    }

    pub fn approve_signer(&self, address: &str) -> Result<(), Error> {
        let path = format!("/api/v1/evm/signers/{}/approve", urlencoding::encode(address));
        let _ = self
            .transport
            .request_raw(Method::POST, &path, Option::<&()>::None, Some(&[200]))?;
        Ok(())
    }

    pub fn transfer_ownership(&self, address: &str, req: &TransferOwnershipRequest) -> Result<(), Error> {
        let path = format!("/api/v1/evm/signers/{}/transfer", urlencoding::encode(address));
        let _ = self
            .transport
            .request_raw(Method::POST, &path, Some(req), Some(&[200]))?;
        Ok(())
    }

    pub fn delete_signer(&self, address: &str) -> Result<(), Error> {
        let path = format!("/api/v1/evm/signers/{}", urlencoding::encode(address));
        let _ = self
            .transport
            .request_raw(Method::DELETE, &path, Option::<&()>::None, Some(&[204]))?;
        Ok(())
    }

    pub fn grant_access(&self, address: &str, req: &GrantAccessRequest) -> Result<(), Error> {
        let path = format!("/api/v1/evm/signers/{}/access", urlencoding::encode(address));
        let _ = self
            .transport
            .request_raw(Method::POST, &path, Some(req), Some(&[200]))?;
        Ok(())
    }

    pub fn revoke_access(&self, address: &str, api_key_id: &str) -> Result<(), Error> {
        let path = format!(
            "/api/v1/evm/signers/{}/access/{}",
            urlencoding::encode(address),
            urlencoding::encode(api_key_id)
        );
        let _ = self
            .transport
            .request_raw(Method::DELETE, &path, Option::<&()>::None, Some(&[200]))?;
        Ok(())
    }

    pub fn list_access(&self, address: &str) -> Result<Vec<SignerAccessEntry>, Error> {
        let path = format!("/api/v1/evm/signers/{}/access", urlencoding::encode(address));
        self.transport
            .request_json(Method::GET, &path, Option::<&()>::None, Some(&[200]))
    }
}
