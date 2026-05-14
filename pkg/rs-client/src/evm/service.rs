use std::time::Duration;

use crate::transport::transport::Transport;

use super::{GuardService, HdWalletService, RequestService, RuleService, SignService, SignerService};

#[derive(Clone)]
pub struct Service {
    pub sign: SignService,
    pub requests: RequestService,
    pub rules: RuleService,
    pub signers: SignerService,
    pub hdwallets: HdWalletService,
    pub guard: GuardService,
}

impl Service {
    pub fn new(transport: Transport, poll_interval: Duration, poll_timeout: Duration) -> Self {
        let sign = SignService::new(transport.clone(), poll_interval, poll_timeout);
        Self {
            requests: RequestService::new(transport.clone()),
            rules: RuleService::new(transport.clone()),
            signers: SignerService::new(transport.clone()),
            hdwallets: HdWalletService::new(transport.clone()),
            guard: GuardService::new(transport),
            sign,
        }
    }
}
