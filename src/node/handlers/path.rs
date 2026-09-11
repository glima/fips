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
use crate::proto::link::PathMessage;
use crate::transport::{TransportAddr, TransportId};
use tracing::{debug, trace};

impl Node {
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

        let Some(peer) = self.peers.get_mut(&node_addr) else {
            return;
        };
        if peer.transport_id() == Some(transport_id) {
            // The active path: the handshake proved it, and it is kept
            // alive by heartbeats, not probes.
            return;
        }
        peer.add_path(transport_id, remote_addr.clone());
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
        let Some(peer) = self.peers.get_mut(from) else {
            return;
        };
        let was_live = peer
            .path_on(transport_id)
            .is_some_and(|p| p.state() == crate::peer::PathState::Live);
        match peer.note_path_ack(transport_id, ack.probe_id, ack.remote_active, now_ms) {
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

    /// A transport's presence came back: clear the probe backoff on every
    /// path over it so the next discovery tick may probe at once.
    pub(in crate::node) fn reset_probe_backoff_on_transport(&mut self, transport_id: TransportId) {
        for peer in self.peers.values_mut() {
            peer.reset_probe_backoff_on(transport_id);
        }
    }
}
