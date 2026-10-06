//! Hole punching through an endpoint-dependent ("symmetric") NAT: the spray side.
//!
//! A symmetric NAT gives every (socket, destination) pair its own public port, so the
//! single reflexive address learned by QAD is useless to the remote. The birthday-paradox
//! strategy (as used by Tailscale) makes up for it with numbers: this side sends one
//! datagram each from `N` extra sockets to the remote's public address, creating `N`
//! mappings at ports it does not know, and tells the remote to probe `M` random ports.
//! With `N * M` a good fraction of the port space, one probe lands on one mapping with
//! high probability.
//!
//! A probe that lands arrives on one of the extra sockets. The mapping it came through is
//! bound to that socket, so from then on everything for that remote has to leave through
//! the same socket: the socket is *pinned* to the remote and the senders consult
//! [`SprayState::pinned`] before picking a socket.
//!
//! Only IPv4 is sprayed; symmetric NAT is an IPv4 phenomenon.

use std::{
    collections::HashMap,
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU8, Ordering},
    },
    task::{Context, Poll},
    time::{Duration, Instant},
};

use netwatch::UdpSocket;
use tracing::{debug, trace, warn};

use super::RecvInfo;

/// Number of extra sockets to spray from.
pub(crate) const SPRAY_SOCKETS: usize = 256;
/// How long unpinned spray sockets are kept after a spray, for the remote's probes to land.
const SPRAY_TTL: Duration = Duration::from_secs(8);
/// A pinned socket is released after this long without receiving anything.
const PINNED_IDLE: Duration = Duration::from_secs(90);
/// What a spray datagram contains. Too short to be mistaken for a QUIC packet, long enough
/// for every NAT to create a mapping.
const SPRAY_PAYLOAD: [u8; 4] = [0; 4];

/// Whether this endpoint should spray, from the `IROH_HOLEPUNCH_SPRAY` environment variable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SprayPolicy {
    /// Never spray.
    Off,
    /// Spray when net_report found that this endpoint's NAT mapping varies by destination.
    Auto,
    /// Spray on every hole punching round (for labs that only have one QAD server, so
    /// net_report cannot tell the NAT type).
    Always,
}

impl SprayPolicy {
    fn from_env() -> Self {
        match std::env::var("IROH_HOLEPUNCH_SPRAY").as_deref() {
            Ok("off") | Ok("0") => Self::Off,
            Ok("always") => Self::Always,
            Ok(other) if !other.is_empty() && other != "auto" => {
                warn!("IROH_HOLEPUNCH_SPRAY={other:?} not understood, using auto");
                Self::Auto
            }
            _ => Self::Auto,
        }
    }
}

const NAT_UNKNOWN: u8 = 0;
const NAT_EASY: u8 = 1;
const NAT_HARD: u8 = 2;

/// Spray sockets and the remotes pinned to them, shared between the receiving side of
/// the transports, all senders and the per-remote actors.
#[derive(Debug, Clone)]
pub(crate) struct SprayState(Arc<Inner>);

#[derive(Debug)]
struct Inner {
    policy: SprayPolicy,
    /// Fast path for the senders: nothing is pinned.
    any_pinned: AtomicBool,
    /// Fast path for the receiver: no sockets at all.
    any_sockets: AtomicBool,
    /// What net_report found about our IPv4 NAT, as `NAT_*`.
    nat: AtomicU8,
    sockets: Mutex<Sockets>,
}

#[derive(Debug, Default)]
struct Sockets {
    list: Vec<SpraySocket>,
    /// Remote (canonical address) → index into `list`.
    pinned: HashMap<SocketAddr, usize>,
    last_spray: Option<Instant>,
}

#[derive(Debug)]
struct SpraySocket {
    socket: Arc<UdpSocket>,
    created: Instant,
    last_recv: Option<Instant>,
}

impl Default for SprayState {
    fn default() -> Self {
        Self(Arc::new(Inner {
            policy: SprayPolicy::from_env(),
            any_pinned: AtomicBool::new(false),
            any_sockets: AtomicBool::new(false),
            nat: AtomicU8::new(NAT_UNKNOWN),
            sockets: Mutex::new(Sockets::default()),
        }))
    }
}

impl SprayState {
    /// Records what net_report found about the IPv4 NAT mapping.
    pub(crate) fn set_mapping_varies_by_dest(&self, varies: Option<bool>) {
        let nat = match varies {
            None => NAT_UNKNOWN,
            Some(false) => NAT_EASY,
            Some(true) => NAT_HARD,
        };
        if self.0.nat.swap(nat, Ordering::Relaxed) != nat {
            debug!(?varies, "spray: NAT mapping varies by destination");
        }
    }

    /// Whether net_report could not tell the NAT type (e.g. only one QAD server).
    pub(crate) fn nat_unknown(&self) -> bool {
        self.0.policy == SprayPolicy::Auto && self.0.nat.load(Ordering::Relaxed) == NAT_UNKNOWN
    }

    /// Whether this endpoint should spray on its hole punching rounds.
    pub(crate) fn should_spray(&self) -> bool {
        match self.0.policy {
            SprayPolicy::Off => false,
            SprayPolicy::Always => true,
            SprayPolicy::Auto => self.0.nat.load(Ordering::Relaxed) == NAT_HARD,
        }
    }

    /// Sends one datagram to each of `targets` from each of [`SPRAY_SOCKETS`] fresh sockets.
    ///
    /// Returns how many sockets were sprayed from. Only IPv4 targets are used.
    pub(crate) fn spray(&self, targets: &[SocketAddr]) -> usize {
        let targets: Vec<SocketAddr> = targets
            .iter()
            .filter(|a| matches!(a.ip(), IpAddr::V4(ip) if !ip.is_loopback()))
            .copied()
            .collect();
        if targets.is_empty() {
            return 0;
        }
        let mut sockets = self.0.sockets.lock().expect("poisoned");
        let now = Instant::now();
        sockets.expire(now, &self.0);
        let mut count = 0;
        let mut fresh = Vec::with_capacity(SPRAY_SOCKETS);
        for _ in 0..SPRAY_SOCKETS {
            let socket = match UdpSocket::bind_full((Ipv4Addr::UNSPECIFIED, 0)) {
                Ok(socket) => Arc::new(socket),
                Err(err) => {
                    debug!(count, "spray: binding socket failed: {err:#}");
                    break;
                }
            };
            fresh.push(socket.clone());
            sockets.list.push(SpraySocket {
                socket,
                created: now,
                last_recv: None,
            });
            count += 1;
        }
        // A fresh socket's writability is not known to the reactor yet, so sending has to
        // be polled; do that off the caller, the datagrams are out within milliseconds.
        debug!(count, ?targets, "spraying");
        n0_future::task::spawn(async move {
            for socket in fresh {
                for target in &targets {
                    let transmit = noq_udp::Transmit {
                        destination: *target,
                        ecn: None,
                        contents: &SPRAY_PAYLOAD,
                        segment_size: None,
                        src_ip: None,
                    };
                    if let Err(err) =
                        std::future::poll_fn(|cx| socket.poll_send_noq(cx, &transmit)).await
                    {
                        trace!(%target, "spray: send failed: {err:#}");
                    }
                }
            }
        });
        sockets.last_spray = Some(now);
        self.0
            .any_sockets
            .store(!sockets.list.is_empty(), Ordering::Release);
        debug!(count, "sprayed");
        count
    }

    /// Drops all spray sockets and pins, e.g. on a network change: their NAT mappings are
    /// gone with it.
    pub(crate) fn clear(&self) {
        let mut sockets = self.0.sockets.lock().expect("poisoned");
        if !sockets.list.is_empty() {
            debug!(
                sockets = sockets.list.len(),
                pinned = sockets.pinned.len(),
                "spray: cleared"
            );
        }
        sockets.list.clear();
        sockets.pinned.clear();
        self.0.any_pinned.store(false, Ordering::Release);
        self.0.any_sockets.store(false, Ordering::Release);
    }

    /// Forgets the pin for `remote`: one of the regular sockets heard from it.
    ///
    /// A pin is only right while the spray socket's mapping is the only way to reach the
    /// remote. Once the remote reaches a regular socket, that path works both ways and
    /// sending from the spray socket would only make the remote see us from a second
    /// port.
    pub(crate) fn unpin(&self, remote: SocketAddr) {
        if !self.0.any_pinned.load(Ordering::Acquire) {
            return;
        }
        let remote = canonical(remote);
        let mut sockets = self.0.sockets.lock().expect("poisoned");
        if sockets.pinned.remove(&remote).is_some() {
            debug!(%remote, "spray: remote reached a regular socket, unpinned");
            self.0
                .any_pinned
                .store(!sockets.pinned.is_empty(), Ordering::Release);
        }
    }

    /// The socket pinned to `remote`, if any.
    pub(crate) fn pinned(&self, remote: SocketAddr) -> Option<Arc<UdpSocket>> {
        if !self.0.any_pinned.load(Ordering::Acquire) {
            return None;
        }
        let remote = canonical(remote);
        let sockets = self.0.sockets.lock().expect("poisoned");
        sockets
            .pinned
            .get(&remote)
            .and_then(|i| sockets.list.get(*i))
            .map(|s| s.socket.clone())
    }

    /// Receives on the spray sockets, pinning a socket to the remote that reached it.
    ///
    /// The received addresses are reported like [`super::ip::IpTransport::poll_recv`] does.
    pub(crate) fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [io::IoSliceMut<'_>],
        metas: &mut [noq_udp::RecvMeta],
        recv_infos: &mut [RecvInfo],
    ) -> Poll<io::Result<usize>> {
        if !self.0.any_sockets.load(Ordering::Acquire) {
            return Poll::Pending;
        }
        let mut sockets = self.0.sockets.lock().expect("poisoned");
        let now = Instant::now();
        sockets.expire(now, &self.0);
        for i in 0..sockets.list.len() {
            match sockets.list[i].socket.poll_recv_noq(cx, bufs, metas) {
                Poll::Pending => {}
                Poll::Ready(Err(err)) => {
                    debug!("spray: recv error: {err:#}");
                }
                Poll::Ready(Ok(n)) => {
                    sockets.list[i].last_recv = Some(now);
                    for (meta, recv_info) in metas.iter_mut().zip(recv_infos.iter_mut()).take(n) {
                        let remote = canonical(meta.addr);
                        if sockets.pinned.insert(remote, i) != Some(i) {
                            debug!(%remote, local = ?sockets.list[i].socket.local_addr().ok(), "spray: remote reached a spray socket, pinned");
                            self.0.any_pinned.store(true, Ordering::Release);
                        }
                        // noq sees a single AF_INET6 socket, so IPv4 shows as mapped.
                        if let IpAddr::V4(ip) = meta.addr.ip() {
                            meta.addr =
                                SocketAddr::new(ip.to_ipv6_mapped().into(), meta.addr.port());
                        }
                        *recv_info = RecvInfo::from_addr(remote.into());
                    }
                    return Poll::Ready(Ok(n));
                }
            }
        }
        Poll::Pending
    }
}

impl Sockets {
    /// Drops spray sockets nobody will use anymore: unpinned ones once the remote's probes
    /// have had time to land, pinned ones that went idle.
    fn expire(&mut self, now: Instant, inner: &Inner) {
        if self.list.is_empty() {
            return;
        }
        let mut keep = Vec::with_capacity(self.list.len());
        let mut index_map = vec![None; self.list.len()];
        let pinned_indices: std::collections::HashSet<usize> =
            self.pinned.values().copied().collect();
        for (i, s) in self.list.drain(..).enumerate() {
            let is_pinned = pinned_indices.contains(&i);
            let alive = if is_pinned {
                s.last_recv
                    .is_none_or(|t| now.duration_since(t) < PINNED_IDLE)
            } else {
                now.duration_since(s.created) < SPRAY_TTL
            };
            if alive {
                index_map[i] = Some(keep.len());
                keep.push(s);
            }
        }
        let dropped = index_map.iter().filter(|m| m.is_none()).count();
        if dropped > 0 {
            trace!(dropped, kept = keep.len(), "spray: expired sockets");
        }
        self.list = keep;
        self.pinned.retain(|_, i| match index_map[*i] {
            Some(new) => {
                *i = new;
                true
            }
            None => false,
        });
        inner
            .any_pinned
            .store(!self.pinned.is_empty(), Ordering::Release);
        inner
            .any_sockets
            .store(!self.list.is_empty(), Ordering::Release);
    }
}

fn canonical(addr: SocketAddr) -> SocketAddr {
    SocketAddr::new(addr.ip().to_canonical(), addr.port())
}
