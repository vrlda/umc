//! Stable application-facing error categories (sdk.md §25).
use umc_control::proto::umc::api::v1::StatusCode;

/// Backend-independent SDK error. Transport adapters may attach richer
/// details through [`crate::client::ClientError`], but application code can
/// match this enum without depending on the daemon transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SdkError {
    Authentication,
    PermissionDenied,
    InvalidArgument,
    NotFound,
    AlreadyExists,
    DeadlineExceeded,
    Cancelled,
    ResourceExhausted,
    FlowControl,
    StreamReset,
    StreamClosed,
    SessionClosed,
    SessionSuspended,
    Transport,
    Unimplemented,
    Unavailable,
    DataLoss,
    Conflict,
    Internal,
}

impl SdkError {
    /// Maps a Control API status code to the stable SDK category.
    #[must_use]
    pub fn from_status(code: i32) -> Self {
        match StatusCode::try_from(code).unwrap_or(StatusCode::Unknown) {
            StatusCode::Cancelled => Self::Cancelled,
            StatusCode::InvalidArgument => Self::InvalidArgument,
            StatusCode::DeadlineExceeded => Self::DeadlineExceeded,
            StatusCode::NotFound => Self::NotFound,
            StatusCode::AlreadyExists => Self::AlreadyExists,
            StatusCode::PermissionDenied => Self::PermissionDenied,
            StatusCode::Unauthenticated => Self::Authentication,
            StatusCode::ResourceExhausted => Self::ResourceExhausted,
            StatusCode::Unimplemented => Self::Unimplemented,
            StatusCode::Unavailable => Self::Unavailable,
            StatusCode::DataLoss => Self::DataLoss,
            StatusCode::Conflict => Self::Conflict,
            StatusCode::Ok
            | StatusCode::Unknown
            | StatusCode::FailedPrecondition
            | StatusCode::Aborted
            | StatusCode::OutOfRange
            | StatusCode::Internal
            | StatusCode::IdempotencyConflict => Self::Internal,
        }
    }
}
