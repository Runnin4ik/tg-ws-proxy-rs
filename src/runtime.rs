//! Shared per-process runtime state.
//!
//! Holds what every connection needs but nothing owns: the outbound connector
//! and the always-on domain-fronting SNI.  The DC lookups are stateless
//! pass-throughs to `config`, kept as methods so call sites can take
//! everything they need from one place.

use std::net::IpAddr;

use crate::config::{default_dc_ip, websocket_dc};
use crate::outbound::OutboundConnector;

pub struct Runtime {
    outbound: OutboundConnector,
    /// Preferred Cloudflare edges from `--cf-ip`. Empty means DNS picks the
    /// anycast edge as usual.
    cf_ips: Vec<IpAddr>,
    /// Domain-fronting SNI, when enabled via `--fronting-domain`. `None` means
    /// fronting is disabled entirely; `Some` means every direct-WebSocket
    /// connect presents it as the SNI — unconditionally, with no trigger
    /// conditions and no cooldown windows (see #111: a reactive switch sends
    /// the real `telegram.org` SNI first, which networks that RST it on sight
    /// never let through).
    fronting_domain: Option<String>,
}

impl Runtime {
    pub fn new(outbound: OutboundConnector) -> Self {
        Self {
            outbound,
            cf_ips: Vec::new(),
            fronting_domain: None,
        }
    }

    /// Configure preferred Cloudflare edges (`--cf-ip`).
    pub fn with_cf_ips(mut self, ips: Vec<IpAddr>) -> Self {
        self.cf_ips = ips;
        self
    }

    /// Configure domain fronting. `domain: None` keeps it disabled.
    pub fn with_fronting(mut self, domain: Option<String>) -> Self {
        self.fronting_domain = domain;
        self
    }

    pub fn outbound(&self) -> &OutboundConnector {
        &self.outbound
    }

    pub fn cf_ips(&self) -> &[IpAddr] {
        &self.cf_ips
    }

    pub fn websocket_dc(&self, dc: u32) -> u32 {
        websocket_dc(dc)
    }

    pub fn fallback_ip(&self, dc: u32) -> Option<&'static str> {
        default_dc_ip(dc)
    }

    /// The configured fronting SNI, if fronting is enabled.
    pub fn fronting_domain(&self) -> Option<&str> {
        self.fronting_domain.as_deref()
    }
}
