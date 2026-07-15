//! Birthday-paradox candidate generation for endpoint-dependent ("symmetric") NAT.
//!
//! When a peer is behind an endpoint-dependent-mapping NAT (detected via
//! [`net_report`]'s `mapping_varies_by_dest`), a single PATH_CHALLENGE to the
//! peer's one observed `ip:port` will miss: that mapping only applies to the
//! flow that created it. The birthday-paradox strategy (as used by Tailscale's
//! magicsock) has the *easy* side probe many randomized destination ports on the
//! hard side's public IP, while the hard side sprays from many source ports so
//! one of the (source,dest) pairs lands. This module generates the easy side's
//! randomized destination candidates; the hard-side source-port spray lives in
//! the QUIC/noq socket layer (see docs/decisions/iroh-birthday-paradox-implementation-plan.md).
//!
//! The RNG is injected so the unit is pure and deterministic under test.

use std::collections::BTreeSet;
use std::net::{IpAddr, SocketAddr};

/// Lowest port we will probe. Below 1024 are privileged/system ports that NAT
/// devices essentially never assign as an outbound mapping.
const MIN_PORT: u16 = 1024;

/// Generate up to `n` distinct candidate [`SocketAddr`]s at randomized ports on
/// `public_ip`, for probing a peer behind an endpoint-dependent (symmetric) NAT.
///
/// The peer's already-observed `known_port` (if non-zero) is always included as
/// one candidate. Remaining candidates draw ports from `next_port` (an injected
/// RNG), keeping only ports `>= MIN_PORT`, de-duplicated. Bounded so a degenerate
/// RNG cannot loop forever.
pub(crate) fn birthday_paradox_candidates(
    public_ip: IpAddr,
    known_port: u16,
    n: usize,
    mut next_port: impl FnMut() -> u16,
) -> Vec<SocketAddr> {
    let mut ports: BTreeSet<u16> = BTreeSet::new();
    if known_port >= MIN_PORT {
        ports.insert(known_port);
    }
    let mut guard = 0usize;
    let cap = n.saturating_mul(20).max(1);
    while ports.len() < n && guard < cap {
        let p = next_port();
        if p >= MIN_PORT {
            ports.insert(p);
        }
        guard += 1;
    }
    ports
        .into_iter()
        .map(|p| SocketAddr::new(public_ip, p))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    /// Tiny deterministic LCG so tests don't depend on a real rng crate.
    struct Lcg(u64);
    impl Lcg {
        fn port(&mut self) -> u16 {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1);
            (self.0 >> 33) as u16
        }
    }

    fn ip() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7))
    }

    #[test]
    fn never_exceeds_n_and_dedups() {
        let mut rng = Lcg(42);
        let out = birthday_paradox_candidates(ip(), 41641, 256, || rng.port());
        assert!(out.len() <= 256);
        let set: BTreeSet<_> = out.iter().collect();
        assert_eq!(set.len(), out.len(), "candidates must be unique");
    }

    #[test]
    fn includes_known_port() {
        let mut rng = Lcg(1);
        let out = birthday_paradox_candidates(ip(), 50000, 16, || rng.port());
        assert!(out.iter().any(|a| a.port() == 50000 && a.ip() == ip()));
    }

    #[test]
    fn all_ports_are_non_privileged() {
        let mut rng = Lcg(7);
        let out = birthday_paradox_candidates(ip(), 0, 64, || rng.port());
        assert!(out.iter().all(|a| a.port() >= MIN_PORT));
    }

    #[test]
    fn zero_known_port_is_skipped_not_emitted() {
        let mut rng = Lcg(9);
        let out = birthday_paradox_candidates(ip(), 0, 8, || rng.port());
        assert!(out.iter().all(|a| a.port() != 0));
    }

    #[test]
    fn deterministic_under_seeded_rng() {
        let mut a = Lcg(123);
        let mut b = Lcg(123);
        let oa = birthday_paradox_candidates(ip(), 1234, 32, || a.port());
        let ob = birthday_paradox_candidates(ip(), 1234, 32, || b.port());
        assert_eq!(oa, ob);
    }

    #[test]
    fn degenerate_rng_terminates() {
        // RNG that only ever returns a privileged port -> loop must still bound out.
        let out = birthday_paradox_candidates(ip(), 0, 100, || 80);
        assert!(out.is_empty()); // nothing >= MIN_PORT, but it returned (no hang)
    }
}
