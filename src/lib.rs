//! rustdesk-tunnel core: campus-aware tunnel that pulls remote services to
//! localhost via a self-hosted RustDesk relay, with an SSH layer inside the
//! tunnel providing the end-to-end data encryption.

pub mod app;
pub mod config;
pub mod crypto;
pub mod frame;
pub mod mangle;
pub mod probe;
pub mod proto;
pub mod rendezvous;
pub mod relay;
pub mod session;
pub mod ssh;
