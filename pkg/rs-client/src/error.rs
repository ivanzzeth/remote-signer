use thiserror::Error;

#[derive(Debug, Clone)]
pub struct ErrorResponse {
    pub error: String,
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct ApiError {
    pub status_code: u16,
    pub code: String,
    pub message: String,
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.message.is_empty() {
            write!(f, "API error {}: {}", self.status_code, self.code)
        } else {
            write!(f, "API error {} ({}): {}", self.status_code, self.code, self.message)
        }
    }
}

impl std::error::Error for ApiError {}

#[derive(Debug, Clone)]
pub struct SignError {
    pub request_id: String,
    pub status: String,
    pub message: String,
}

impl std::fmt::Display for SignError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.message.is_empty() {
            write!(f, "sign error [{}] status={}", self.request_id, self.status)
        } else {
            write!(f, "sign error [{}] status={}: {}", self.request_id, self.status, self.message)
        }
    }
}

impl std::error::Error for SignError {}

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid config: {0}")]
    InvalidConfig(String),

    #[error("http request failed: {0}")]
    RequestFailed(String),

    #[error(transparent)]
    Api(#[from] ApiError),

    #[error(transparent)]
    Json(#[from] serde_json::Error),

    #[error(transparent)]
    Url(#[from] url::ParseError),

    #[error("timeout waiting for approval")]
    Timeout,

    #[error("unauthorized: invalid or expired api key/signature")]
    Unauthorized,

    #[error("not found")]
    NotFound,

    #[error("signer not found")]
    SignerNotFound,

    #[error("invalid payload")]
    InvalidPayload,

    #[error("rate limited")]
    RateLimited,

    #[error("pending manual approval")]
    PendingApproval,

    #[error("request rejected")]
    Rejected,

    #[error("request blocked by rule")]
    Blocked,

    #[error(transparent)]
    Sign(#[from] SignError),
}

impl Error {
    pub fn from_api_error(e: ApiError) -> Self {
        match e.status_code {
            401 => Error::Unauthorized,
            404 => Error::NotFound,
            429 => Error::RateLimited,
            400 => {
                if e.code == "signer_not_found" {
                    return Error::SignerNotFound;
                }
                if e.code == "invalid_payload" {
                    return Error::InvalidPayload;
                }
                Error::Api(e)
            }
            _ => Error::Api(e),
        }
    }
}
