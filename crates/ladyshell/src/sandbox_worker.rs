//! Provider-neutral, versioned worker transport for a capped sandbox.
//!
//! The explicitly selected worker implements this contract. Application requests
//! and observation replies are opaque to Ladyshell. See `docs/sandbox-worker.md`
//! in the version-matched resources for locking, sealing and storage obligations.

pub const BINARY: &str = "/usr/local/bin/sandbox-worker";
pub const MAX_BYTES: u32 = 16384;
pub const PROTOCOL: &str = "ladyshell-worker-v1";
pub const EXECUTE_ARGS: [&str; 5] = [
    BINARY,
    "sandbox-execute",
    "/var/lib/ladyshell/broker/control",
    "/var/lib/ladyshell/broker/artifacts",
    "/var/lib/ladyshell/broker/incoming",
];
pub const OBSERVE_ARGS: [&str; 5] = [
    BINARY,
    "sandbox-observe",
    "/var/lib/ladyshell/broker/control",
    "/var/lib/ladyshell/broker/artifacts",
    "/var/lib/ladyshell/broker/incoming",
];
pub(crate) const CONTROL_ARGS: [&str; 5] = [
    BINARY,
    "sandbox-control",
    "/var/lib/ladyshell/broker/control",
    "/var/lib/ladyshell/broker/artifacts",
    "/var/lib/ladyshell/broker/incoming",
];
