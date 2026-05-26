use std::time::Duration;

use crate::transport::transport::Transport;

use super::{BroadcastService, GuardService, HdWalletService, RequestService, RuleService, SignService, SignerService, SimulateService};

#[derive(Clone)]
pub struct Service {
    pub sign: SignService,
    pub requests: RequestService,
    pub rules: RuleService,
    pub signers: SignerService,
    pub hdwallets: HdWalletService,
    pub guard: GuardService,
    pub broadcast: BroadcastService,
    pub simulate: SimulateService,
}

impl Service {
    pub fn new(transport: Transport, poll_interval: Duration, poll_timeout: Duration) -> Self {
        let sign = SignService::new(transport.clone(), poll_interval, poll_timeout);
        Self {
            requests: RequestService::new(transport.clone()),
            rules: RuleService::new(transport.clone()),
            signers: SignerService::new(transport.clone()),
            hdwallets: HdWalletService::new(transport.clone()),
            broadcast: BroadcastService::new(transport.clone()),
            simulate: SimulateService::new(transport.clone()),
            guard: GuardService::new(transport),
            sign,
        }
    }
}
