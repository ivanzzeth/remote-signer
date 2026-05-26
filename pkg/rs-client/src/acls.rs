use reqwest::Method;
use serde::{Deserialize, Serialize};

use crate::error::Error;
use crate::transport::transport::Transport;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpWhitelistResponse {
    pub enabled: bool,
    pub allowed_ips: Vec<String>,
    pub trust_proxy: bool,
    pub trusted_proxies: Vec<String>,
}

#[derive(Clone)]
pub struct Service {
    transport: Transport,
}

impl Service {
    pub fn new(transport: Transport) -> Self {
        Self { transport }
    }

    pub fn get_ip_whitelist(&self) -> Result<IpWhitelistResponse, Error> {
        self.transport
            .request_json(Method::GET, "/api/v1/acls/ip-whitelist", Option::<&()>::None, Some(&[200]))
    }
}
