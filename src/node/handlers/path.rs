//! Path probe / path ack: adding a second path to a peer under the session
//! it already has.
//!
//! `reference/fips-multi-path-switchover.md` §4. A probe is an ordinary
//! encrypted frame sent on a candidate transport. The receiver, having
//! decrypted it against the session found by index, has proof the peer is
//! reachable on that `(transport, addr)`: it adds the path as `Probing`,
//! marks it `rx_live`, and answers with an ack **on that same path**. The
//! prober's receipt of the ack proves the reverse direction: the path goes
//! `Live`, `tx_live`, and takes an RTT sample. No handshake, no new key
//! material, no index allocation.
//!
//! Nothing here changes which path a peer sends on. That is selection, a
//! later step; today `active` never moves after promotion.

use crate::NodeAddr;
use crate::node::Node;
use crate::peer::{PathPolicy, PathSwitch, PathWithdrawal};
use crate::proto::link::PathMessage;
use crate::transport::{TransportAddr, TransportId};
use tracing::{debug, info, trace};

impl Node {
    /// The selection knobs, from `node.path.*`.
    pub(in crate::node) fn path_policy(&self) -> PathPolicy {
        let cfg = &self.config().node.path;
        let standby_ms = self
            .config()
            .node
            .heartbeat_interval_secs
            .saturating_mul(1000);
        PathPolicy {
            margin: cfg.switch_margin,
            dwell_ms: cfg.switch_dwell_secs.saturating_mul(1000),
            min_samples: cfg.min_samples,
            rtt_window_ms: standby_ms
                .saturating_mul(u64::from(cfg.min_samples).max(1))
                .saturating_mul(2)
                .max(30_000),
        }
    }

    /// The role of the transport `transport_id`, or `Normal` if it is not
    /// registered.
    fn transport_role(&self, transport_id: TransportId) -> crate::config::TransportRole {
        self.transports
            .get(&transport_id)
            .map(|t| t.role())
            .unwrap_or_default()
    }

    /// Run selection for every peer. Called from the tick. A switch here is
    /// discretionary or pinned, or mandatory after a `Suspect` mark that
    /// nothing else acted on; the presence edge runs its own.
    pub(in crate::node) fn run_path_selection(&mut self) {
        let policy = self.path_policy();
        let now_ms = crate::time::mono_ms();
        let switches: Vec<(NodeAddr, PathSwitch)> = self
            .peers
            .iter_mut()
            .filter_map(|(addr, peer)| peer.select_path(now_ms, &policy).map(|s| (*addr, s)))
            .collect();
        for (node_addr, switch) in switches {
            info!(
                peer = %self.peer_display_name(&node_addr),
                from_transport = %switch.from.0,
                to_transport = %switch.to.0,
                to_addr = %switch.to.1,
                reason = ?switch.reason,
                "Path switched, session kept"
            );
            self.apply_path_switch(&node_addr, switch.to);
        }
    }

    /// Pin a peer's traffic to its path on `transport_id`. Applies on the
    /// next selection run. `false` if the peer or the path is unknown.
    #[allow(dead_code)] // wired by `fipsctl path pin`
    pub(crate) fn pin_peer_path(
        &mut self,
        node_addr: &NodeAddr,
        transport_id: TransportId,
    ) -> bool {
        self.peers
            .get_mut(node_addr)
            .is_some_and(|p| p.pin_path(transport_id))
    }

    /// Clear a peer's pin. `false` if the peer is unknown.
    #[allow(dead_code)] // wired by `fipsctl path unpin`
    pub(crate) fn unpin_peer_path(&mut self, node_addr: &NodeAddr) -> bool {
        match self.peers.get_mut(node_addr) {
            Some(p) => {
                p.unpin_paths();
                true
            }
            None => false,
        }
    }

    /// Probe `transport_id`/`remote_addr` as a path to a live peer, if the
    /// per-path backoff allows it.
    ///
    /// Adds the path as `Probing` on first use, so a transport that never
    /// answers (an old node that drops `0x52` at debug) is probed at the
    /// backoff cadence and never becomes eligible. The backoff doubles per
    /// unanswered probe from the tick interval, capped at the heartbeat
    /// interval, and is reset when the transport's presence cycles.
    pub(in crate::node) async fn maybe_probe_path(
        &mut self,
        node_addr: NodeAddr,
        transport_id: TransportId,
        remote_addr: TransportAddr,
    ) {
        let now_ms = crate::time::mono_ms();
        let base_ms = self
            .config()
            .node
            .tick_interval_secs
            .saturating_mul(1000)
            .max(100);
        let cap_ms = self
            .config()
            .node
            .heartbeat_interval_secs
            .saturating_mul(1000)
            .max(base_ms);

        let role = self.transport_role(transport_id);
        let Some(peer) = self.peers.get_mut(&node_addr) else {
            return;
        };
        if peer.transport_id() == Some(transport_id) {
            // The active path: the handshake proved it, and it is kept
            // alive by heartbeats, not probes.
            return;
        }
        peer.add_path(transport_id, remote_addr.clone())
            .set_role(role);
        let Some((probe_id, remote_active)) =
            peer.take_probe(transport_id, now_ms, base_ms, cap_ms)
        else {
            return;
        };
        // The address the beacon carried is the one to reach the peer at
        // on this transport, and it may have moved since the path was added.
        let probe = PathMessage {
            probe_id,
            remote_active,
        };
        match self
            .send_encrypted_link_message_on_path(
                &node_addr,
                &probe.encode_probe(),
                transport_id,
                remote_addr.clone(),
            )
            .await
        {
            Ok(()) => trace!(
                peer = %self.peer_display_name(&node_addr),
                transport_id = %transport_id,
                remote_addr = %remote_addr,
                probe_id,
                "Sent path probe"
            ),
            Err(e) => debug!(
                peer = %self.peer_display_name(&node_addr),
                transport_id = %transport_id,
                remote_addr = %remote_addr,
                error = %e,
                "Path probe send failed"
            ),
        }
    }

    /// A `PathProbe` arrived from `from` on `arrival`.
    ///
    /// The frame decrypted under `from`'s session, so `from` is reachable
    /// over `arrival`. Record the path and answer on it. The ack says
    /// whether `arrival` is the path *we* send on, which it usually is not.
    pub(in crate::node) async fn handle_path_probe(
        &mut self,
        from: &NodeAddr,
        payload: &[u8],
        arrival: (TransportId, &TransportAddr),
    ) {
        let probe = match PathMessage::decode(payload) {
            Ok(p) => p,
            Err(e) => {
                debug!(peer = %self.peer_display_name(from), error = %e, "Malformed path probe");
                return;
            }
        };
        let (transport_id, remote_addr) = arrival;
        let now_ms = crate::time::mono_ms();
        let role = self.transport_role(transport_id);
        let Some(peer) = self.peers.get_mut(from) else {
            return;
        };
        let was_new = peer.path_on(transport_id).is_none();
        peer.note_path_probe(
            transport_id,
            remote_addr.clone(),
            probe.remote_active,
            now_ms,
        );
        if was_new {
            peer.set_path_role(transport_id, role);
        }
        let ours_active = peer.transport_id() == Some(transport_id);
        if was_new {
            debug!(
                peer = %self.peer_display_name(from),
                transport_id = %transport_id,
                remote_addr = %remote_addr,
                "Peer probed a new path; added"
            );
        }

        let ack = PathMessage {
            probe_id: probe.probe_id,
            remote_active: ours_active,
        };
        if let Err(e) = self
            .send_encrypted_link_message_on_path(
                from,
                &ack.encode_ack(),
                transport_id,
                remote_addr.clone(),
            )
            .await
        {
            debug!(
                peer = %self.peer_display_name(from),
                transport_id = %transport_id,
                error = %e,
                "Path ack send failed"
            );
        }
    }

    /// A `PathAck` arrived from `from` on `arrival`: our probe on that path
    /// reached the peer and the answer reached us, so the path works in
    /// both directions.
    pub(in crate::node) fn handle_path_ack(
        &mut self,
        from: &NodeAddr,
        payload: &[u8],
        arrival: (TransportId, &TransportAddr),
    ) {
        let ack = match PathMessage::decode(payload) {
            Ok(a) => a,
            Err(e) => {
                debug!(peer = %self.peer_display_name(from), error = %e, "Malformed path ack");
                return;
            }
        };
        let (transport_id, _) = arrival;
        let now_ms = crate::time::mono_ms();
        let window_ms = self.path_policy().rtt_window_ms;
        let Some(peer) = self.peers.get_mut(from) else {
            return;
        };
        let was_live = peer
            .path_on(transport_id)
            .is_some_and(|p| p.state() == crate::peer::PathState::Live);
        match peer.note_path_ack(
            transport_id,
            ack.probe_id,
            ack.remote_active,
            now_ms,
            window_ms,
        ) {
            Some(rtt_ms) if !was_live => debug!(
                peer = %self.peer_display_name(from),
                transport_id = %transport_id,
                rtt_ms,
                "Path live"
            ),
            Some(rtt_ms) => trace!(
                peer = %self.peer_display_name(from),
                transport_id = %transport_id,
                rtt_ms,
                "Path ack"
            ),
            None => trace!(
                peer = %self.peer_display_name(from),
                transport_id = %transport_id,
                probe_id = ack.probe_id,
                "Path ack matched no outstanding probe"
            ),
        }
    }

    /// A transport's presence went away: withdraw the path every peer held
    /// over it. Returns how many peers were reaped for want of another path.
    ///
    /// For each peer: the path goes `Dead` with its history kept. If it was
    /// a standby, nothing else happens. If it was the active path and an
    /// eligible standby exists, traffic moves there now, under the same
    /// session, and the switch side effects run
    /// ([`apply_path_switch`](Self::apply_path_switch)). Only a peer with
    /// no eligible path left is reaped, through the same routed link-dead
    /// teardown the liveness reaper uses.
    ///
    /// The peer machine sees nothing while any path remains: a switch is
    /// not a link event. Deliberately undamped, like the reap it grew from.
    pub(in crate::node) async fn withdraw_transport(&mut self, transport_id: TransportId) -> usize {
        let now_ms = crate::time::mono_ms();
        let policy = self.path_policy();
        let affected: Vec<NodeAddr> = self
            .peers
            .iter()
            .filter(|(_, peer)| peer.path_on(transport_id).is_some())
            .map(|(node_addr, _)| *node_addr)
            .collect();
        if affected.is_empty() {
            return 0;
        }

        let wall_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        let mut reaped = 0;
        for node_addr in affected {
            let outcome = match self.peers.get_mut(&node_addr) {
                Some(peer) => peer.withdraw_path(transport_id, now_ms, &policy),
                None => continue,
            };
            match outcome {
                PathWithdrawal::NoPath => {}
                PathWithdrawal::Standby => debug!(
                    peer = %self.peer_display_name(&node_addr),
                    %transport_id,
                    "Standby path withdrawn: its interface went away"
                ),
                PathWithdrawal::Switched { from, to } => {
                    info!(
                        peer = %self.peer_display_name(&node_addr),
                        from_transport = %from.0,
                        to_transport = %to.0,
                        to_addr = %to.1,
                        "Active path withdrawn: traffic moved to the standby, session kept"
                    );
                    self.apply_path_switch(&node_addr, to);
                }
                PathWithdrawal::NoAlternative => {
                    self.reap_peer_without_path(node_addr, transport_id, wall_ms)
                        .await;
                    reaped += 1;
                }
            }
        }
        reaped
    }

    /// Everything that follows the peer's active path changing to `to`.
    ///
    /// A switch is also an MTU change, and three things size traffic from
    /// the peer's transport without re-running on their own
    /// (`reference/fips-multi-path-switchover.md` §5):
    ///
    /// - the peer's `path_mtu_lookup` seed, which only ever tightens within
    ///   a link and would leave one cable→BLE excursion clamping every new
    ///   flow to this peer at the BLE MTU after fail-back; its relinked
    ///   branch is the hook, so re-seed from the new path;
    /// - the per-session source MTU, which tightens on the next send anyway
    ///   but only loosens after tens of seconds; tighten it now for every
    ///   session this peer is the next hop of, so the TUN gate answers with
    ///   PTB instead of losing the first packet per flow at the transport;
    /// - the node-wide MSS ceiling.
    ///
    /// The link record follows the traffic so everything that reports the
    /// peer's transport and address by link stays truthful; the control
    /// machine is keyed on the link and is untouched.
    pub(in crate::node) fn apply_path_switch(
        &mut self,
        node_addr: &NodeAddr,
        to: (TransportId, TransportAddr),
    ) {
        let (transport_id, addr) = to;
        if let Some(link_id) = self.peers.get(node_addr).map(|p| p.link_id())
            && let Some(link) = self.links.get_mut(&link_id)
        {
            self.addr_to_link.retain(|_, mapped| *mapped != link_id);
            link.rebind(transport_id, addr.clone());
            self.addr_to_link
                .insert((transport_id, addr.clone()), link_id);
        }

        self.seed_path_mtu_for_link_peer(node_addr, transport_id, &addr);

        let link_mtu = self
            .transports
            .get(&transport_id)
            .map(|t| t.link_mtu(&addr));
        if let Some(link_mtu) = link_mtu {
            let dests: Vec<NodeAddr> = self.sessions.keys().copied().collect();
            for dest in dests {
                let via_peer = self
                    .find_next_hop(&dest)
                    .is_some_and(|hop| hop.node_addr() == node_addr);
                if !via_peer {
                    continue;
                }
                if let Some(mmp) = self.sessions.get_mut(&dest).and_then(|s| s.mmp_mut()) {
                    mmp.path_mtu.seed_source_mtu(link_mtu);
                }
            }
        }

        self.refresh_tun_mss_ceiling();
    }

    /// A transport's presence came back: clear the probe backoff on every
    /// path over it so the next discovery tick may probe at once.
    pub(in crate::node) fn reset_probe_backoff_on_transport(&mut self, transport_id: TransportId) {
        for peer in self.peers.values_mut() {
            peer.reset_probe_backoff_on(transport_id);
        }
    }
}
