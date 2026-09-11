//! Index-only demux: the first step of the multi-path switchover design
//! (`reference/fips-multi-path-switchover.md`, §3).
//!
//! A session index is unique across transports, so a frame carrying a known
//! `receiver_idx` decrypts no matter which transport delivered it. That opens
//! cross-transport delivery, and two rules keep it closed to a relay:
//!
//! 1. an authentic frame from another transport is delivered but does not
//!    move the peer (`ActivePeer::set_current_addr` freezes the transport);
//! 2. a decrypt failure on a transport the peer is not on is not counted
//!    toward the force-removal threshold.

use super::connected_udp::{
    PROMOTED_ADDR, far_side_frame, promoted_peer_with_the_far_side_session,
};
use super::*;
use crate::proto::fmp::wire::{build_encrypted, build_established_header};

/// Where a frame "from the wifi" claims to come from.
const OTHER_ADDR: &str = "10.0.0.7:2121";

/// Threshold constant in node/dataplane/encrypted.rs.
const THRESHOLD: u32 = 20;

/// A well-formed established header over random bytes that no session will
/// authenticate.
fn garbage_frame(receiver_idx: SessionIndex, counter: u64) -> Vec<u8> {
    let junk = [0xA5u8; 48];
    let header = build_established_header(receiver_idx, counter, 0, junk.len() as u16);
    build_encrypted(&header, &junk)
}

#[tokio::test]
async fn an_authentic_frame_on_another_transport_is_delivered_but_does_not_move_the_peer() {
    let cable = TransportId::new(1);
    let wifi = TransportId::new(2);
    let (mut node, node_addr, our_index, mut far_side) =
        promoted_peer_with_the_far_side_session(cable);

    // One prior failure, so a successful decrypt is observable as the reset.
    node.handle_decrypt_failure(&node_addr);
    assert_eq!(
        node.get_peer(&node_addr)
            .unwrap()
            .consecutive_decrypt_failures(),
        1
    );

    let frame = far_side_frame(&mut far_side, our_index);
    node.handle_encrypted_frame(ReceivedPacket::new(
        wifi,
        TransportAddr::from_string(OTHER_ADDR),
        frame,
    ))
    .await;

    let peer = node
        .get_peer(&node_addr)
        .expect("an authentic frame never removes a peer");
    assert_eq!(
        peer.consecutive_decrypt_failures(),
        0,
        "the frame must have been found by index and authenticated"
    );
    assert_eq!(
        peer.transport_id(),
        Some(cable),
        "an authentic frame on another transport must not move the peer's send side"
    );
    assert_eq!(
        peer.current_addr(),
        Some(&TransportAddr::from_string(PROMOTED_ADDR)),
        "nor its address"
    );
}

#[tokio::test]
async fn an_authentic_frame_on_the_bound_transport_still_roams_the_address() {
    let cable = TransportId::new(1);
    let (mut node, node_addr, our_index, mut far_side) =
        promoted_peer_with_the_far_side_session(cable);

    let frame = far_side_frame(&mut far_side, our_index);
    node.handle_encrypted_frame(ReceivedPacket::new(
        cable,
        TransportAddr::from_string(OTHER_ADDR),
        frame,
    ))
    .await;

    let peer = node.get_peer(&node_addr).unwrap();
    assert_eq!(peer.transport_id(), Some(cable));
    assert_eq!(
        peer.current_addr(),
        Some(&TransportAddr::from_string(OTHER_ADDR)),
        "roaming inside the bound transport is unchanged"
    );
}

#[tokio::test]
async fn garbage_from_a_transport_the_peer_is_not_on_is_not_counted() {
    let cable = TransportId::new(1);
    let wifi = TransportId::new(2);
    let (mut node, node_addr, our_index, _far_side) =
        promoted_peer_with_the_far_side_session(cable);

    for counter in 0..(THRESHOLD * 2) as u64 {
        node.handle_encrypted_frame(ReceivedPacket::new(
            wifi,
            TransportAddr::from_string(OTHER_ADDR),
            garbage_frame(our_index, counter),
        ))
        .await;
    }

    let peer = node
        .get_peer(&node_addr)
        .expect("garbage from a transport the peer is not on must not tear it down");
    assert_eq!(
        peer.consecutive_decrypt_failures(),
        0,
        "off-path failures are dropped, not counted"
    );
}

#[tokio::test]
async fn garbage_on_the_bound_transport_still_counts() {
    let cable = TransportId::new(1);
    let (mut node, node_addr, our_index, _far_side) =
        promoted_peer_with_the_far_side_session(cable);

    for counter in 0..THRESHOLD as u64 {
        node.handle_encrypted_frame(ReceivedPacket::new(
            cable,
            TransportAddr::from_string(PROMOTED_ADDR),
            garbage_frame(our_index, counter),
        ))
        .await;
    }

    assert!(
        node.get_peer(&node_addr).is_none(),
        "the threshold still applies on the transport the peer is on"
    );
    assert!(
        !node.peers_by_index.contains_key(&our_index.as_u32()),
        "and the index entry goes with it"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn a_worker_failure_report_is_charged_only_on_the_bound_transport() {
    use crate::node::decrypt_worker::DecryptFailureReport;

    let cable = TransportId::new(1);
    let wifi = TransportId::new(2);
    let (mut node, node_addr, _our_index, _far_side) =
        promoted_peer_with_the_far_side_session(cable);

    node.process_decrypt_failure_report(DecryptFailureReport {
        source_node_addr: node_addr,
        transport_id: wifi,
        fmp_counter: 7,
        fmp_replay_highest: 0,
    })
    .await;
    assert_eq!(
        node.get_peer(&node_addr)
            .unwrap()
            .consecutive_decrypt_failures(),
        0,
        "a worker report from a transport the peer is not on is not counted"
    );

    node.process_decrypt_failure_report(DecryptFailureReport {
        source_node_addr: node_addr,
        transport_id: cable,
        fmp_counter: 8,
        fmp_replay_highest: 0,
    })
    .await;
    assert_eq!(
        node.get_peer(&node_addr)
            .unwrap()
            .consecutive_decrypt_failures(),
        1,
        "one from the bound transport is"
    );
}

#[test]
fn set_current_addr_roams_inside_the_bound_transport_only() {
    let cable = TransportId::new(1);
    let wifi = TransportId::new(2);
    let mut peer = crate::peer::ActivePeer::new(make_peer_identity(), LinkId::new(1), 0);

    // Unbound: the first sighting binds.
    assert!(peer.set_current_addr(cable, TransportAddr::from_string("10.0.0.1:1")));
    assert_eq!(peer.transport_id(), Some(cable));

    // Same transport, new address: a roam.
    assert!(peer.set_current_addr(cable, TransportAddr::from_string("10.0.0.1:2")));
    assert_eq!(
        peer.current_addr(),
        Some(&TransportAddr::from_string("10.0.0.1:2"))
    );

    // Same transport, same address: nothing changed.
    assert!(!peer.set_current_addr(cable, TransportAddr::from_string("10.0.0.1:2")));

    // Another transport: refused, nothing moved.
    assert!(!peer.set_current_addr(wifi, TransportAddr::from_string("10.0.0.7:1")));
    assert_eq!(peer.transport_id(), Some(cable));
    assert_eq!(
        peer.current_addr(),
        Some(&TransportAddr::from_string("10.0.0.1:2"))
    );

    // The deliberate rebind crosses.
    assert!(peer.rebind_transport(wifi, TransportAddr::from_string("10.0.0.7:1")));
    assert_eq!(peer.transport_id(), Some(wifi));
    assert_eq!(
        peer.current_addr(),
        Some(&TransportAddr::from_string("10.0.0.7:1"))
    );
}

#[test]
fn a_promoted_peer_holds_one_path_and_rebind_repoints_it() {
    let cable = TransportId::new(1);
    let wifi = TransportId::new(2);
    let (node, node_addr, _our_index, _far_side) = promoted_peer_with_the_far_side_session(cable);
    let peer = node.get_peer(&node_addr).unwrap();
    assert_eq!(peer.paths().len(), 1, "promotion binds exactly one path");
    assert_eq!(peer.active_path().map(|p| p.transport_id()), Some(cable));
    assert_eq!(
        peer.active_path().map(|p| p.addr()),
        Some(&TransportAddr::from_string(PROMOTED_ADDR))
    );

    // Until the probe exchange adds paths, a rebind re-points the single
    // path rather than growing the set.
    let mut peer = crate::peer::ActivePeer::new(make_peer_identity(), LinkId::new(1), 0);
    assert!(peer.paths().is_empty());
    assert!(peer.rebind_transport(cable, TransportAddr::from_string("10.0.0.1:1")));
    assert!(peer.rebind_transport(wifi, TransportAddr::from_string("10.0.0.7:1")));
    assert_eq!(peer.paths().len(), 1);
    assert_eq!(peer.transport_id(), Some(wifi));
}

// ============================================================================
// Path probe / path ack (design §4)
// ============================================================================

use super::spanning_tree::{
    LOOPBACK_REGISTRY, TestNode, initiate_handshake, make_test_node, next_loopback_addr,
    process_available_packets,
};
use crate::peer::PathState;
use crate::proto::link::PathMessage;
use crate::transport::TransportHandle;
use crate::transport::loopback::LoopbackTransport;

/// The second transport both nodes share, standing in for the wifi next
/// to the cable that `TestNode` comes with.
fn wifi() -> TransportId {
    TransportId::new(2)
}

/// Give `node` a second loopback transport, `wifi()`, on a fresh address that
/// delivers into the node's existing packet channel. Returns that address.
fn add_wifi(node: &mut TestNode) -> TransportAddr {
    let addr = next_loopback_addr();
    let tx = LOOPBACK_REGISTRY
        .lock()
        .unwrap()
        .get(&node.addr)
        .cloned()
        .expect("the node's cable address is registered");
    LOOPBACK_REGISTRY.lock().unwrap().insert(addr.clone(), tx);
    let transport = LoopbackTransport::new(wifi(), addr.clone(), LOOPBACK_REGISTRY.clone());
    node.node
        .transports
        .insert(wifi(), TransportHandle::Loopback(transport));
    addr
}

/// Two nodes peered over the cable, each also reachable over `wifi()`.
/// Returns `(nodes, wifi_addr_of_0, wifi_addr_of_1)`.
async fn dual_homed_pair() -> (Vec<TestNode>, TransportAddr, TransportAddr) {
    let mut nodes = vec![make_test_node().await, make_test_node().await];
    let wifi_0 = add_wifi(&mut nodes[0]);
    let wifi_1 = add_wifi(&mut nodes[1]);
    initiate_handshake(&mut nodes, 0, 1).await;
    for _ in 0..10 {
        if process_available_packets(&mut nodes).await == 0 {
            break;
        }
    }
    assert_eq!(nodes[0].node.peer_count(), 1, "peered over the cable");
    assert_eq!(nodes[1].node.peer_count(), 1, "peered over the cable");
    (nodes, wifi_0, wifi_1)
}

#[test]
fn path_message_round_trips_on_the_wire() {
    let probe = PathMessage {
        probe_id: 0xDEAD_BEEF,
        remote_active: true,
    };
    let wire = probe.encode_probe();
    assert_eq!(wire[0], 0x52);
    assert_eq!(PathMessage::decode(&wire[1..]).unwrap(), probe);

    let ack = PathMessage {
        probe_id: 7,
        remote_active: false,
    };
    let wire = ack.encode_ack();
    assert_eq!(wire[0], 0x53);
    assert_eq!(PathMessage::decode(&wire[1..]).unwrap(), ack);

    assert!(PathMessage::decode(&wire[1..4]).is_err(), "short payload");
}

#[tokio::test]
async fn a_probe_adds_a_path_at_both_ends_and_the_ack_makes_it_live() {
    let (mut nodes, wifi_0, _wifi_1) = dual_homed_pair().await;
    let addr_0 = *nodes[0].node.node_addr();
    let addr_1 = *nodes[1].node.node_addr();
    let cable = nodes[0].transport_id;

    // Node 1 probes node 0 over the wifi.
    nodes[1]
        .node
        .maybe_probe_path(addr_0, wifi(), wifi_0.clone())
        .await;
    {
        let peer = nodes[1].node.get_peer(&addr_0).unwrap();
        let path = peer
            .path_on(wifi())
            .expect("the prober adds the path first");
        assert_eq!(path.state(), PathState::Probing);
        assert!(path.tx_live_at_ms().is_none());
    }

    // Probe reaches node 0.
    assert_eq!(process_available_packets(&mut nodes).await, 1);
    {
        let peer = nodes[0].node.get_peer(&addr_1).unwrap();
        let path = peer.path_on(wifi()).expect("the receiver adds the path");
        assert_eq!(
            path.state(),
            PathState::Probing,
            "hearing is not proof of the reverse"
        );
        assert!(path.rx_live_at_ms().is_some());
        assert!(!path.remote_active(), "node 1 still sends on the cable");
        assert_eq!(peer.transport_id(), Some(cable), "nothing switched");
        assert_eq!(peer.paths().len(), 2);
    }

    // Ack reaches node 1.
    assert_eq!(process_available_packets(&mut nodes).await, 1);
    {
        let peer = nodes[1].node.get_peer(&addr_0).unwrap();
        let path = peer.path_on(wifi()).unwrap();
        assert_eq!(path.state(), PathState::Live);
        assert!(path.tx_live_at_ms().is_some());
        assert!(path.last_rtt_ms().is_some());
        assert!(!path.remote_active(), "node 0 still sends on the cable");
        assert_eq!(peer.transport_id(), Some(cable), "nothing switched");
    }

    // One session, one index: no handshake was started anywhere.
    assert_eq!(nodes[0].node.peer_count(), 1);
    assert_eq!(nodes[1].node.peer_count(), 1);
    assert!(
        !nodes[1]
            .node
            .is_connecting_to_peer_on_path(&addr_0, wifi(), &wifi_0)
    );
}

#[tokio::test]
async fn a_beacon_from_a_live_peer_on_a_new_transport_probes_instead_of_dialling() {
    let (mut nodes, wifi_0, _wifi_1) = dual_homed_pair().await;
    let addr_0 = *nodes[0].node.node_addr();
    let pubkey_0 = nodes[0].node.identity().pubkey();

    // Node 1 hears node 0 beacon on the wifi.
    match nodes[1].node.transports.get(&wifi()).unwrap() {
        TransportHandle::Loopback(t) => t.inject_discovered(wifi_0.clone(), pubkey_0),
        _ => unreachable!(),
    }
    nodes[1].node.poll_transport_discovery().await;

    assert!(
        !nodes[1]
            .node
            .is_connecting_to_peer_on_path(&addr_0, wifi(), &wifi_0),
        "a live peer is probed, not dialled"
    );
    assert_eq!(
        nodes[1]
            .node
            .get_peer(&addr_0)
            .unwrap()
            .path_on(wifi())
            .map(|p| p.state()),
        Some(PathState::Probing)
    );

    // Probe out, ack back.
    assert_eq!(process_available_packets(&mut nodes).await, 1);
    assert_eq!(process_available_packets(&mut nodes).await, 1);
    assert_eq!(
        nodes[1]
            .node
            .get_peer(&addr_0)
            .unwrap()
            .path_on(wifi())
            .map(|p| p.state()),
        Some(PathState::Live)
    );
}

#[tokio::test]
async fn an_unanswered_probe_backs_off_and_presence_return_resets_it() {
    let (mut nodes, wifi_0, _wifi_1) = dual_homed_pair().await;
    let addr_0 = *nodes[0].node.node_addr();

    // Two ticks back to back: one probe, the second held by the backoff.
    nodes[1]
        .node
        .maybe_probe_path(addr_0, wifi(), wifi_0.clone())
        .await;
    nodes[1]
        .node
        .maybe_probe_path(addr_0, wifi(), wifi_0.clone())
        .await;
    assert_eq!(
        nodes[0].packet_rx.len(),
        1,
        "the backoff holds the second probe"
    );

    // Presence cycles on the wifi: the backoff is cleared.
    nodes[1].node.reset_probe_backoff_on_transport(wifi());
    nodes[1]
        .node
        .maybe_probe_path(addr_0, wifi(), wifi_0.clone())
        .await;
    assert_eq!(nodes[0].packet_rx.len(), 2);

    // The path is still unproven.
    assert_eq!(
        nodes[1]
            .node
            .get_peer(&addr_0)
            .unwrap()
            .path_on(wifi())
            .map(|p| p.state()),
        Some(PathState::Probing)
    );
}

#[tokio::test]
async fn an_ack_for_no_outstanding_probe_changes_nothing() {
    let (mut nodes, _wifi_0, wifi_1) = dual_homed_pair().await;
    let addr_1 = *nodes[1].node.node_addr();

    let stale = PathMessage {
        probe_id: 99,
        remote_active: false,
    };
    nodes[0]
        .node
        .handle_path_ack(&addr_1, &stale.encode_ack()[1..], (wifi(), &wifi_1));
    assert!(
        nodes[0]
            .node
            .get_peer(&addr_1)
            .unwrap()
            .path_on(wifi())
            .is_none(),
        "an ack never creates a path; only a probe does"
    );
}

#[tokio::test]
async fn the_active_path_is_not_probed() {
    let (mut nodes, _wifi_0, _wifi_1) = dual_homed_pair().await;
    let addr_0 = *nodes[0].node.node_addr();
    let cable = nodes[0].transport_id;
    let cable_addr_0 = nodes[0].addr.clone();

    nodes[1]
        .node
        .maybe_probe_path(addr_0, cable, cable_addr_0)
        .await;
    assert_eq!(
        nodes[0].packet_rx.len(),
        0,
        "the handshake proved the active path"
    );
}
