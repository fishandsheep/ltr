//! LTR (Local-to-Remote) is an async-Rust TCP tunnel that exposes local ports
//! through a remote relay, with transport encryption on by default and an
//! embedded Web console. Wire-compatible with Bore v1 clients and servers.
//!
//! This is the library crate documentation. If you're looking for usage
//! information about the binary, see the command below.
//!
//! ```shell
//! $ ltr help
//! ```
//!
//! There are two components to the crate, offering implementations of the
//! server network daemon and client local forwarding proxy. Both are public
//! members and can be run programmatically with a Tokio 1.0 runtime.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

/// CLI argument parsing and command dispatch.
pub mod cli;
pub mod shared;
/// Local web console for managing client tunnels.
pub mod web;

pub use ltr_relay::{auth, client, server, transport};
