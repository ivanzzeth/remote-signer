//! EVM endpoint paths and query strings.
//!
//! Extracted so the blocking and async services build identical URLs. Path
//! segments are percent-encoded; query parameters are only appended when set.

use super::{ListRequestsFilter, ListRulesFilter, ListSignersFilter};

fn enc(s: &str) -> String {
    urlencoding::encode(s).into_owned()
}

fn with_query(mut path: String, params: Vec<String>) -> String {
    if !params.is_empty() {
        path.push('?');
        path.push_str(&params.join("&"));
    }
    path
}

// ---------------------------------------------------------------- sign

pub(crate) const SIGN: &str = "/api/v1/evm/sign";
pub(crate) const SIGN_BATCH: &str = "/api/v1/evm/sign/batch";

// ------------------------------------------------------------ requests

pub(crate) const REQUESTS: &str = "/api/v1/evm/requests";

pub(crate) fn request(request_id: &str) -> String {
    format!("/api/v1/evm/requests/{}", enc(request_id))
}

pub(crate) fn request_approve(request_id: &str) -> String {
    format!("/api/v1/evm/requests/{}/approve", enc(request_id))
}

pub(crate) fn request_preview_rule(request_id: &str) -> String {
    format!("/api/v1/evm/requests/{}/preview-rule", enc(request_id))
}

pub(crate) fn request_simulation(request_id: &str) -> String {
    format!("/api/v1/evm/requests/{}/simulation", enc(request_id))
}

pub(crate) fn requests_list(filter: Option<&ListRequestsFilter>) -> String {
    let mut params = vec![];
    if let Some(f) = filter {
        if let Some(v) = &f.status {
            params.push(format!("status={}", enc(v)));
        }
        if let Some(v) = &f.signer_address {
            params.push(format!("signer_address={}", enc(v)));
        }
        if let Some(v) = &f.chain_id {
            params.push(format!("chain_id={}", enc(v)));
        }
        if let Some(v) = f.limit {
            params.push(format!("limit={v}"));
        }
        if let Some(v) = &f.cursor {
            params.push(format!("cursor={}", enc(v)));
        }
        if let Some(v) = &f.cursor_id {
            params.push(format!("cursor_id={}", enc(v)));
        }
    }
    with_query(REQUESTS.to_string(), params)
}

// ------------------------------------------------------------- signers

pub(crate) const SIGNERS: &str = "/api/v1/evm/signers";

pub(crate) fn signer(address: &str) -> String {
    format!("/api/v1/evm/signers/{}", enc(address))
}

pub(crate) fn signer_unlock(address: &str) -> String {
    format!("/api/v1/evm/signers/{}/unlock", enc(address))
}

pub(crate) fn signer_lock(address: &str) -> String {
    format!("/api/v1/evm/signers/{}/lock", enc(address))
}

pub(crate) fn signer_approve(address: &str) -> String {
    format!("/api/v1/evm/signers/{}/approve", enc(address))
}

pub(crate) fn signer_transfer(address: &str) -> String {
    format!("/api/v1/evm/signers/{}/transfer", enc(address))
}

pub(crate) fn signer_access(address: &str) -> String {
    format!("/api/v1/evm/signers/{}/access", enc(address))
}

pub(crate) fn signer_access_entry(address: &str, api_key_id: &str) -> String {
    format!(
        "/api/v1/evm/signers/{}/access/{}",
        enc(address),
        enc(api_key_id)
    )
}

pub(crate) fn signers_list(filter: Option<&ListSignersFilter>) -> String {
    let mut params = vec![];
    if let Some(f) = filter {
        if let Some(v) = &f.signer_type {
            params.push(format!("type={}", enc(v)));
        }
        if let Some(v) = f.limit {
            params.push(format!("limit={v}"));
        }
        if let Some(v) = f.offset {
            params.push(format!("offset={v}"));
        }
    }
    with_query(SIGNERS.to_string(), params)
}

// --------------------------------------------------------------- rules

pub(crate) const RULES: &str = "/api/v1/evm/rules";

pub(crate) fn rule(rule_id: &str) -> String {
    format!("/api/v1/evm/rules/{}", enc(rule_id))
}

pub(crate) fn rule_budgets(rule_id: &str) -> String {
    format!("/api/v1/evm/rules/{}/budgets", enc(rule_id))
}

pub(crate) fn rule_approve(rule_id: &str) -> String {
    format!("/api/v1/evm/rules/{}/approve", enc(rule_id))
}

pub(crate) fn rule_reject(rule_id: &str) -> String {
    format!("/api/v1/evm/rules/{}/reject", enc(rule_id))
}

pub(crate) fn rule_propose(rule_id: &str) -> String {
    format!("/api/v1/evm/rules/{}/propose", enc(rule_id))
}

pub(crate) fn rules_list(filter: Option<&ListRulesFilter>) -> String {
    let mut params = vec![];
    if let Some(f) = filter {
        if let Some(v) = &f.chain_type {
            params.push(format!("chain_type={}", enc(v)));
        }
        if let Some(v) = &f.signer_address {
            params.push(format!("signer_address={}", enc(v)));
        }
        if let Some(v) = &f.api_key_id {
            params.push(format!("api_key_id={}", enc(v)));
        }
        if let Some(v) = &f.rule_type {
            params.push(format!("type={}", enc(v)));
        }
        if let Some(v) = &f.mode {
            params.push(format!("mode={}", enc(v)));
        }
        if let Some(v) = f.enabled {
            params.push(format!("enabled={v}"));
        }
        if let Some(v) = f.limit {
            params.push(format!("limit={v}"));
        }
        if let Some(v) = f.offset {
            params.push(format!("offset={v}"));
        }
    }
    with_query(RULES.to_string(), params)
}

// ----------------------------------------------------------- hdwallets

pub(crate) const HD_WALLETS: &str = "/api/v1/evm/hd-wallets";

pub(crate) fn hd_wallet_derive(primary_addr: &str) -> String {
    format!("/api/v1/evm/hd-wallets/{}/derive", enc(primary_addr))
}

pub(crate) fn hd_wallet_derived(primary_addr: &str) -> String {
    format!("/api/v1/evm/hd-wallets/{}/derived", enc(primary_addr))
}

// -------------------------------------------------- guard / broadcast / simulate

pub(crate) const GUARD_RESUME: &str = "/api/v1/evm/guard/resume";
pub(crate) const BROADCAST: &str = "/api/v1/evm/broadcast";
pub(crate) const SIMULATE: &str = "/api/v1/evm/simulate";
pub(crate) const SIMULATE_BATCH: &str = "/api/v1/evm/simulate/batch";
pub(crate) const SIMULATE_STATUS: &str = "/api/v1/evm/simulate/status";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_paths_have_no_query_when_filter_absent() {
        assert_eq!(requests_list(None), "/api/v1/evm/requests");
        assert_eq!(signers_list(None), "/api/v1/evm/signers");
        assert_eq!(rules_list(None), "/api/v1/evm/rules");
    }

    #[test]
    fn list_paths_skip_unset_fields() {
        let filter = ListRequestsFilter {
            status: Some("pending".to_string()),
            limit: Some(10),
            ..Default::default()
        };
        assert_eq!(
            requests_list(Some(&filter)),
            "/api/v1/evm/requests?status=pending&limit=10"
        );
    }

    #[test]
    fn list_paths_encode_query_values() {
        let filter = ListRequestsFilter {
            cursor: Some("a b&c=d".to_string()),
            ..Default::default()
        };
        assert_eq!(
            requests_list(Some(&filter)),
            "/api/v1/evm/requests?cursor=a%20b%26c%3Dd"
        );
    }

    #[test]
    fn rules_list_maps_rule_type_to_type_param() {
        let filter = ListRulesFilter {
            rule_type: Some("budget".to_string()),
            enabled: Some(true),
            ..Default::default()
        };
        assert_eq!(
            rules_list(Some(&filter)),
            "/api/v1/evm/rules?type=budget&enabled=true"
        );
    }

    #[test]
    fn signers_list_maps_signer_type_to_type_param() {
        let filter = ListSignersFilter {
            signer_type: Some("hd".to_string()),
            offset: Some(20),
            ..Default::default()
        };
        assert_eq!(
            signers_list(Some(&filter)),
            "/api/v1/evm/signers?type=hd&offset=20"
        );
    }

    #[test]
    fn path_segments_are_percent_encoded() {
        // A request id containing a slash must not create an extra path segment.
        assert_eq!(request("a/b"), "/api/v1/evm/requests/a%2Fb");
        assert_eq!(
            signer_access_entry("0xAbC", "key/1"),
            "/api/v1/evm/signers/0xAbC/access/key%2F1"
        );
    }
}
