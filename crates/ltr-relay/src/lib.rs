//! LTR relay and transport implementation.

#![forbid(unsafe_code)]
#![allow(missing_docs)]

pub use ltr_protocol as shared;

/// Callback fired once a long-running component has finished startup and
/// entered its serving phase.
pub type OnReady = Box<dyn FnOnce() + Send>;

pub mod auth;
pub mod client;
pub mod server;
pub mod transport;
