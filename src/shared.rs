//! Compatibility facade for the standalone LTR v1 protocol crate.

pub use ltr_protocol::{
    configure_tcp_stream, ClientMessage, Delimited, ServerMessage, CONTROL_PORT, MAX_FRAME_LENGTH,
    NETWORK_TIMEOUT, TCP_KEEPALIVE_IDLE, TCP_KEEPALIVE_INTERVAL,
};
