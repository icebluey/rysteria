use thiserror::Error;

/// Configuration validation error.
#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("invalid QUIC stream receive window: {0}")]
    InvalidStreamReceiveWindow(String),

    #[error("invalid QUIC connection receive window: {0}")]
    InvalidConnReceiveWindow(String),

    #[error("invalid max idle timeout: {0}")]
    InvalidMaxIdleTimeout(String),

    #[error("invalid keep-alive period: {0}")]
    InvalidKeepAlivePeriod(String),

    #[error("invalid max incoming streams: {0}")]
    InvalidMaxIncomingStreams(String),

    #[error("invalid bandwidth: {0}")]
    InvalidBandwidth(String),

    #[error("invalid UDP idle timeout: {0}")]
    InvalidUdpIdleTimeout(String),

    #[error("{0}")]
    Custom(String),
}

/// Error connecting to the server (client-side).
#[derive(Debug, Error)]
pub enum ConnectError {
    #[error("TLS error: {0}")]
    Tls(String),

    #[error("QUIC connection error: {0}")]
    Quic(String),

    #[error("authentication failed: {0}")]
    AuthFailed(String),

    #[error("protocol error: {0}")]
    Protocol(String),
}

/// Authentication error (server-side).
#[derive(Debug, Error)]
pub enum AuthError {
    #[error("invalid credentials")]
    InvalidCredentials,

    #[error("bandwidth limit exceeded")]
    BandwidthExceeded,

    #[error("authentication backend error: {0}")]
    BackendError(String),
}

/// Error dialing (opening) a remote connection.
#[derive(Debug, Error)]
pub enum DialError {
    #[error("connection closed")]
    Closed,

    #[error("stream open error: {0}")]
    StreamError(String),

    #[error("protocol error: {0}")]
    Protocol(String),

    #[error("remote rejected: {0}")]
    Rejected(String),
}

/// Error indicating the connection is closed.
#[derive(Debug, Error)]
#[error("connection closed")]
pub struct ClosedError;

/// Wire-level protocol error.
#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("invalid address length")]
    InvalidAddressLength,

    #[error("invalid message length")]
    InvalidMessageLength,

    #[error("invalid padding length")]
    InvalidPaddingLength,

    #[error("invalid UTF-8 in address")]
    InvalidUtf8,

    #[error("insufficient data")]
    InsufficientData,

    #[error("varint overflow")]
    VarIntOverflow,

    #[error("{0}")]
    Custom(String),
}
