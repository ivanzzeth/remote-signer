use std::path::Path;

use crate::error::Error;

#[derive(Debug, Clone, Default)]
pub struct TlsConfig {
    pub ca_file: Option<String>,
    pub cert_file: Option<String>,
    pub key_file: Option<String>,
    pub skip_verify: bool,
}

impl TlsConfig {
    pub fn validate_paths(&self) -> Result<(), Error> {
        for p in [&self.ca_file, &self.cert_file, &self.key_file] {
            if let Some(p) = p {
                if !Path::new(p).exists() {
                    return Err(Error::InvalidConfig(format!("TLS file not found: {p}")));
                }
            }
        }
        Ok(())
    }
}
