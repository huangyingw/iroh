//! Birthday-paradox NAT traversal for endpoint-dependent ("symmetric") NAT.
//!
//! Background: a single PATH_CHALLENGE to a symmetric-NAT peer's one observed
//! `ip:port` misses — that mapping only applies to the flow that created it. The
//! birthday-paradox strategy (as used by Tailscale's magicsock) has the *hard*
//! (symmetric) side spray from `N` source ports (creating `N` external mappings
//! toward the peer) while the *easy* side probes `M` randomized destination ports
//! on the hard side's public IP; with `N * M` on the order of the ephemeral port
//! space, a (source,dest) pair collides with high probability.
//!
//! This module is the pure "brain":
//! - [`birthday_paradox_candidates`] — the easy side's `M` randomized probe
//!   targets, fed to noq via `n0_nat_traversal::add_remote_address` (see
//!   `docs/decisions/iroh-birthday-paradox-implementation-plan.md`).
//! - [`collision_probability`] / [`probes_for_target`] — pick `N`/`M` from a
//!   target success probability, shared by both sides.
//!
//! RNG and knobs are injected so the unit is pure and deterministic under test.

use std::collections::BTreeSet;
use std::net::{IpAddr, SocketAddr};

/// Lowest port we will probe/spray. Below 1024 are privileged/system ports that
/// NAT devices essentially never assign as an outbound mapping.
pub(crate) const MIN_PORT: u16 = 1024;

/// Size of the usable ephemeral/registered port space (`1024..=65535`), i.e. the
/// space over which a random source-port mapping and a random probe collide.
pub(crate) const PORT_SPACE: u32 = 65535 - MIN_PORT as u32 + 1;

/// Generate up to `n` distinct candidate [`SocketAddr`]s at randomized ports on
/// `public_ip`, for probing a peer behind an endpoint-dependent (symmetric) NAT.
///
/// The peer's already-observed `known_port` (if `>= MIN_PORT`) is always included.
/// Remaining candidates draw ports from `next_port` (an injected RNG), keeping
/// only ports `>= MIN_PORT`, de-duplicated. Bounded so a degenerate RNG cannot
/// loop forever.
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

/// Probability that at least one of `source_ports` external mappings collides
/// with at least one of `probes` random destination probes, over `port_space`
/// ports. `1 - (1 - source_ports/port_space)^probes`.
pub(crate) fn collision_probability(source_ports: u32, probes: u32, port_space: u32) -> f64 {
    if port_space == 0 || source_ports == 0 || probes == 0 {
        return 0.0;
    }
    let n = source_ports.min(port_space) as f64;
    let miss_one = 1.0 - n / port_space as f64;
    1.0 - miss_one.powi(probes as i32)
}

/// Minimum number of random probes the easy side must send, given the hard side
/// sprays from `source_ports` ports, to reach `target` success probability over
/// `port_space`. Returns `None` if `target` is unreachable (e.g. `source_ports`
/// or `target` out of range).
pub(crate) fn probes_for_target(source_ports: u32, port_space: u32, target: f64) -> Option<u32> {
    if !(0.0..1.0).contains(&target) || source_ports == 0 || port_space == 0 {
        return None;
    }
    let n = source_ports.min(port_space) as f64;
    let miss_one = 1.0 - n / port_space as f64;
    if miss_one <= 0.0 {
        return Some(1); // one probe always hits if we mapped the whole space
    }
    // probes = ceil( ln(1 - target) / ln(miss_one) )
    let probes = ((1.0 - target).ln() / miss_one.ln()).ceil();
    if probes.is_finite() && probes >= 1.0 {
        Some(probes as u32)
    } else {
        None
    }
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
    fn candidates_never_exceed_n_and_dedup() {
        let mut rng = Lcg(42);
        let out = birthday_paradox_candidates(ip(), 41641, 256, || rng.port());
        assert!(out.len() <= 256);
        let set: BTreeSet<_> = out.iter().collect();
        assert_eq!(set.len(), out.len());
    }

    #[test]
    fn candidates_include_known_port_and_skip_privileged() {
        let mut rng = Lcg(1);
        let out = birthday_paradox_candidates(ip(), 50000, 16, || rng.port());
        assert!(out.iter().any(|a| a.port() == 50000));
        assert!(out.iter().all(|a| a.port() >= MIN_PORT));
    }

    #[test]
    fn candidates_zero_known_port_not_emitted_and_terminates() {
        let out = birthday_paradox_candidates(ip(), 0, 100, || 80); // degenerate rng
        assert!(out.is_empty());
    }

    #[test]
    fn collision_prob_monotonic_and_bounded() {
        let p_lo = collision_probability(64, 100, PORT_SPACE);
        let p_hi = collision_probability(256, 1000, PORT_SPACE);
        assert!(p_lo < p_hi);
        assert!((0.0..=1.0).contains(&p_lo) && (0.0..=1.0).contains(&p_hi));
        assert_eq!(collision_probability(0, 100, PORT_SPACE), 0.0);
    }

    #[test]
    fn tailscale_256x1000_exceeds_98pct() {
        // Tailscale's published figure: 256 source ports + ~1000 probes -> >98%.
        let p = collision_probability(256, 1000, PORT_SPACE);
        assert!(p > 0.98, "expected >0.98, got {p}");
    }

    #[test]
    fn probes_for_target_matches_forward_model() {
        let n = 256;
        let m = probes_for_target(n, PORT_SPACE, 0.98).expect("reachable");
        // sending m probes must actually clear the target...
        assert!(collision_probability(n, m, PORT_SPACE) >= 0.98);
        // ...and one fewer must fall short (tightness of the ceil).
        assert!(collision_probability(n, m - 1, PORT_SPACE) < 0.98);
    }

    #[test]
    fn probes_for_target_rejects_bad_input() {
        assert!(probes_for_target(0, PORT_SPACE, 0.9).is_none());
        assert!(probes_for_target(256, PORT_SPACE, 1.0).is_none());
        assert!(probes_for_target(256, PORT_SPACE, -0.1).is_none());
    }
}
