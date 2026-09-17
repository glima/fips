//! NAT rule management.
//!
//! Manages nftables DNAT/SNAT rules via the rustables netlink API
//! for translating between virtual IPs and FIPS mesh addresses.

use std::collections::HashMap;
use std::net::Ipv6Addr;
use tracing::{debug, info};

use rustables::expr::{
    Cmp, CmpOp, HighLevelPayload, IPv6HeaderField, Immediate, Masquerade, Meta, MetaType, Nat,
    NatType, NetworkHeaderField, Register, TCPHeaderField, TransportHeaderField, UDPHeaderField,
};
use rustables::{Batch, Chain, ChainType, Hook, HookClass, MsgType, ProtocolFamily, Rule, Table};

use crate::config::{PortForward, Proto};

const TABLE_NAME: &str = "fips_gateway";
const PREROUTING_CHAIN: &str = "prerouting";
const POSTROUTING_CHAIN: &str = "postrouting";

/// NAT priority constants (matching nftables standard priorities).
const DSTNAT_PRIORITY: i32 = -100;
const SRCNAT_PRIORITY: i32 = 100;

/// Errors from NAT operations.
#[derive(Debug, thiserror::Error)]
pub enum NatError {
    #[error("nftables error: {0}")]
    Nftables(String),
    #[error("rule not found for virtual IP {0}")]
    RuleNotFound(Ipv6Addr),
}

impl From<rustables::error::QueryError> for NatError {
    fn from(e: rustables::error::QueryError) -> Self {
        NatError::Nftables(e.to_string())
    }
}

impl From<rustables::error::BuilderError> for NatError {
    fn from(e: rustables::error::BuilderError) -> Self {
        NatError::Nftables(e.to_string())
    }
}

/// A virtual IP ↔ mesh address mapping for NAT rule generation.
#[derive(Clone)]
struct NatMapping {
    virtual_ip: Ipv6Addr,
    mesh_addr: Ipv6Addr,
}

/// One object a NAT rebuild sends, named rather than built.
///
/// `rebuild_batches` decides what a rebuild sends and in what order;
/// `send_batches` turns that decision into rustables objects and hands each
/// batch to the kernel. The split is what lets a test see the delete and the
/// recreate share one transaction without a netlink socket, which is the
/// property that keeps the table in the packet path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NatOp {
    Table(MsgType),
    PreChain,
    PostChain,
    /// Masquerade for traffic leaving through `fips0`.
    FipsMasquerade,
    /// DNAT for the mapping with this virtual IP.
    Dnat(Ipv6Addr),
    /// SNAT for the mapping with this virtual IP.
    Snat(Ipv6Addr),
    /// DNAT for the port forward at this index in `port_forwards`.
    PortForward(usize),
    /// LAN-side masquerade, emitted once when any port forward exists.
    LanMasquerade,
}

/// NAT rule manager using nftables via rustables netlink API.
///
/// Rebuilds the entire nftables table atomically on every change to
/// avoid relying on kernel rule handle tracking (which rustables
/// doesn't expose). The table is small (one masquerade + two rules
/// per mapping) so this is cheap.
pub struct NatManager {
    table: Table,
    pre_chain: Chain,
    post_chain: Chain,
    /// LAN interface name, used to gate the port-forward LAN-side
    /// masquerade rule (distinct from the fips0 egress masquerade).
    lan_interface: String,
    /// Active mappings keyed by virtual IP.
    mappings: HashMap<Ipv6Addr, NatMapping>,
    /// Inbound port-forward rules.
    port_forwards: Vec<PortForward>,
}

impl NatManager {
    /// Build the manager's state without touching netlink.
    ///
    /// Everything `new` does except sending the first rebuild, so a test can
    /// exercise the batch builder with no socket and no privileges.
    fn with_state(lan_interface: String) -> Self {
        let table = Table::new(ProtocolFamily::Inet).with_name(TABLE_NAME);
        let pre_chain = Chain::new(&table)
            .with_name(PREROUTING_CHAIN)
            .with_type(ChainType::Nat)
            .with_hook(Hook::new(HookClass::PreRouting, DSTNAT_PRIORITY));
        let post_chain = Chain::new(&table)
            .with_name(POSTROUTING_CHAIN)
            .with_type(ChainType::Nat)
            .with_hook(Hook::new(HookClass::PostRouting, SRCNAT_PRIORITY));

        Self {
            table,
            pre_chain,
            post_chain,
            lan_interface,
            mappings: HashMap::new(),
            port_forwards: Vec::new(),
        }
    }

    /// Create the nftables table and NAT chains.
    ///
    /// Installs a masquerade rule for traffic exiting via `fips0` so that
    /// LAN client source addresses are rewritten to the gateway's mesh
    /// address, allowing return traffic to route back through the mesh.
    ///
    /// `lan_interface` is the gateway's LAN-facing interface name,
    /// needed by the port-forward LAN-side masquerade rule.
    pub fn new(lan_interface: String) -> Result<Self, NatError> {
        let mgr = Self::with_state(lan_interface);
        mgr.rebuild()?;

        info!("Created nftables table '{TABLE_NAME}' with NAT chains and fips0 masquerade");
        Ok(mgr)
    }

    /// Replace the current inbound port-forward rule set and rebuild
    /// the nftables table atomically. Pass an empty slice to clear.
    pub fn set_port_forwards(&mut self, forwards: &[PortForward]) -> Result<(), NatError> {
        self.port_forwards = forwards.to_vec();
        self.rebuild()?;
        info!(
            count = self.port_forwards.len(),
            "Applied inbound port forwards"
        );
        Ok(())
    }

    /// Add DNAT and SNAT rules for a virtual IP ↔ mesh address mapping.
    pub fn add_mapping(
        &mut self,
        virtual_ip: Ipv6Addr,
        mesh_addr: Ipv6Addr,
    ) -> Result<(), NatError> {
        self.mappings.insert(
            virtual_ip,
            NatMapping {
                virtual_ip,
                mesh_addr,
            },
        );
        self.rebuild()?;

        debug!(
            virtual_ip = %virtual_ip,
            mesh_addr = %mesh_addr,
            "Added DNAT/SNAT rules"
        );
        Ok(())
    }

    /// Remove DNAT and SNAT rules for a virtual IP mapping.
    pub fn remove_mapping(&mut self, virtual_ip: Ipv6Addr) -> Result<(), NatError> {
        if self.mappings.remove(&virtual_ip).is_none() {
            return Err(NatError::RuleNotFound(virtual_ip));
        }
        self.rebuild()?;

        debug!(virtual_ip = %virtual_ip, "Removed DNAT/SNAT rules");
        Ok(())
    }

    /// Flush all rules and delete the nftables table.
    pub fn cleanup(self) -> Result<(), NatError> {
        let mut batch = Batch::new();
        batch.add(&self.table, MsgType::Del);
        batch
            .send()
            .map_err(|e| NatError::Nftables(e.to_string()))?;

        info!("Deleted nftables table '{TABLE_NAME}'");
        Ok(())
    }

    /// Number of active NAT mappings.
    pub fn mapping_count(&self) -> usize {
        self.mappings.len()
    }

    /// The objects a rebuild sends, grouped into the batches that carry them.
    ///
    /// One batch, always. The kernel applies a batch as a single transaction,
    /// so the table is deleted and recreated without ever leaving the packet
    /// path, and a batch the kernel rejects leaves the previous table in
    /// place. The leading `Add` is what makes the `Del` legal on a first run:
    /// rustables sends a table `Add` with `NLM_F_CREATE` and no `NLM_F_EXCL`,
    /// so it succeeds whether or not the table already exists and the `Del`
    /// that follows always has a target.
    fn rebuild_batches(&self) -> Vec<Vec<NatOp>> {
        let mut ops = vec![
            NatOp::Table(MsgType::Add),
            NatOp::Table(MsgType::Del),
            NatOp::Table(MsgType::Add),
            NatOp::PreChain,
            NatOp::PostChain,
            NatOp::FipsMasquerade,
        ];

        for mapping in self.mappings.values() {
            ops.push(NatOp::Dnat(mapping.virtual_ip));
            ops.push(NatOp::Snat(mapping.virtual_ip));
        }

        // Inbound port-forward rules. Each forward is one DNAT rule in
        // prerouting keyed on (iif fips0, nfproto ipv6, l4proto, th dport).
        // When any forwards are configured, emit a single LAN-side masquerade
        // in postrouting so the LAN target host sees the gateway's LAN address
        // as source and replies flow back through conntrack.
        for index in 0..self.port_forwards.len() {
            ops.push(NatOp::PortForward(index));
        }
        if !self.port_forwards.is_empty() {
            ops.push(NatOp::LanMasquerade);
        }

        vec![ops]
    }

    /// Build each op into its rustables object and send the batches in order.
    fn send_batches(&self, batches: &[Vec<NatOp>]) -> Result<(), NatError> {
        for ops in batches {
            let mut batch = Batch::new();
            for op in ops {
                match *op {
                    NatOp::Table(msg_type) => batch.add(&self.table, msg_type),
                    NatOp::PreChain => batch.add(&self.pre_chain, MsgType::Add),
                    NatOp::PostChain => batch.add(&self.post_chain, MsgType::Add),
                    NatOp::FipsMasquerade => {
                        // Rewrite the source address of traffic leaving fips0.
                        // Without this, LAN clients' source addresses (e.g.
                        // fd02::20) are not routable on the mesh, so return
                        // traffic would be black-holed.
                        let rule = Rule::new(&self.post_chain)?
                            .with_expr(Meta::new(MetaType::OifName))
                            .with_expr(Cmp::new(CmpOp::Eq, b"fips0\0".to_vec()))
                            .with_expr(Masquerade::default());
                        batch.add(&rule, MsgType::Add);
                    }
                    NatOp::Dnat(virtual_ip) => {
                        let mapping = self.mapping(virtual_ip)?;
                        let rule = Rule::new(&self.pre_chain)?
                            .with_expr(Meta::new(MetaType::NfProto))
                            .with_expr(Cmp::new(CmpOp::Eq, [libc::NFPROTO_IPV6 as u8]))
                            .with_expr(
                                HighLevelPayload::Network(NetworkHeaderField::IPv6(
                                    IPv6HeaderField::Daddr,
                                ))
                                .build(),
                            )
                            .with_expr(Cmp::new(CmpOp::Eq, mapping.virtual_ip.octets()))
                            .with_expr(Immediate::new_data(
                                mapping.mesh_addr.octets().to_vec(),
                                Register::Reg1,
                            ))
                            .with_expr(
                                Nat::default()
                                    .with_nat_type(NatType::DNat)
                                    .with_family(ProtocolFamily::Ipv6)
                                    .with_ip_register(Register::Reg1),
                            );
                        batch.add(&rule, MsgType::Add);
                    }
                    NatOp::Snat(virtual_ip) => {
                        let mapping = self.mapping(virtual_ip)?;
                        let rule = Rule::new(&self.post_chain)?
                            .with_expr(Meta::new(MetaType::NfProto))
                            .with_expr(Cmp::new(CmpOp::Eq, [libc::NFPROTO_IPV6 as u8]))
                            .with_expr(
                                HighLevelPayload::Network(NetworkHeaderField::IPv6(
                                    IPv6HeaderField::Saddr,
                                ))
                                .build(),
                            )
                            .with_expr(Cmp::new(CmpOp::Eq, mapping.mesh_addr.octets()))
                            .with_expr(Immediate::new_data(
                                mapping.virtual_ip.octets().to_vec(),
                                Register::Reg1,
                            ))
                            .with_expr(
                                Nat::default()
                                    .with_nat_type(NatType::SNat)
                                    .with_family(ProtocolFamily::Ipv6)
                                    .with_ip_register(Register::Reg1),
                            );
                        batch.add(&rule, MsgType::Add);
                    }
                    NatOp::PortForward(index) => {
                        let pf = self.port_forwards.get(index).expect(
                            "rebuild_batches only emits indices it read from port_forwards",
                        );
                        let l4proto: u8 = match pf.proto {
                            Proto::Tcp => libc::IPPROTO_TCP as u8,
                            Proto::Udp => libc::IPPROTO_UDP as u8,
                        };
                        let dport_field = match pf.proto {
                            Proto::Tcp => TransportHeaderField::Tcp(TCPHeaderField::Dport),
                            Proto::Udp => TransportHeaderField::Udp(UDPHeaderField::Dport),
                        };
                        let target_ip = *pf.target.ip();
                        let target_port_be = pf.target.port().to_be_bytes();

                        let rule = Rule::new(&self.pre_chain)?
                            .with_expr(Meta::new(MetaType::IifName))
                            .with_expr(Cmp::new(CmpOp::Eq, b"fips0\0".to_vec()))
                            .with_expr(Meta::new(MetaType::NfProto))
                            .with_expr(Cmp::new(CmpOp::Eq, [libc::NFPROTO_IPV6 as u8]))
                            .with_expr(Meta::new(MetaType::L4Proto))
                            .with_expr(Cmp::new(CmpOp::Eq, [l4proto]))
                            .with_expr(HighLevelPayload::Transport(dport_field).build())
                            .with_expr(Cmp::new(CmpOp::Eq, pf.listen_port.to_be_bytes().to_vec()))
                            .with_expr(Immediate::new_data(
                                target_ip.octets().to_vec(),
                                Register::Reg1,
                            ))
                            .with_expr(Immediate::new_data(target_port_be.to_vec(), Register::Reg2))
                            .with_expr(
                                Nat::default()
                                    .with_nat_type(NatType::DNat)
                                    .with_family(ProtocolFamily::Ipv6)
                                    .with_ip_register(Register::Reg1)
                                    .with_port_register(Register::Reg2),
                            );
                        batch.add(&rule, MsgType::Add);
                    }
                    NatOp::LanMasquerade => {
                        let mut lan_iface = self.lan_interface.clone().into_bytes();
                        lan_iface.push(0);
                        let rule = Rule::new(&self.post_chain)?
                            .with_expr(Meta::new(MetaType::IifName))
                            .with_expr(Cmp::new(CmpOp::Eq, b"fips0\0".to_vec()))
                            .with_expr(Meta::new(MetaType::OifName))
                            .with_expr(Cmp::new(CmpOp::Eq, lan_iface))
                            .with_expr(Meta::new(MetaType::NfProto))
                            .with_expr(Cmp::new(CmpOp::Eq, [libc::NFPROTO_IPV6 as u8]))
                            .with_expr(Masquerade::default());
                        batch.add(&rule, MsgType::Add);
                    }
                }
            }

            batch
                .send()
                .map_err(|e| NatError::Nftables(e.to_string()))?;
        }
        Ok(())
    }

    /// The mapping an op names, or the error a caller can report.
    fn mapping(&self, virtual_ip: Ipv6Addr) -> Result<&NatMapping, NatError> {
        self.mappings
            .get(&virtual_ip)
            .ok_or(NatError::RuleNotFound(virtual_ip))
    }

    /// Rebuild the entire nftables table with all current rules, in one
    /// netlink transaction.
    fn rebuild(&self) -> Result<(), NatError> {
        self.send_batches(&self.rebuild_batches())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddrV6;

    fn vip(last: u16) -> Ipv6Addr {
        Ipv6Addr::new(0xfd01, 0, 0, 0, 0, 0, 0, last)
    }

    fn mesh(last: u16) -> Ipv6Addr {
        Ipv6Addr::new(0xfd02, 0, 0, 0, 0, 0, 0, last)
    }

    /// A manager holding `count` mappings and no netlink socket.
    fn manager_with_mappings(count: u16) -> NatManager {
        let mut mgr = NatManager::with_state("br-lan".to_string());
        for i in 1..=count {
            mgr.mappings.insert(
                vip(i),
                NatMapping {
                    virtual_ip: vip(i),
                    mesh_addr: mesh(i),
                },
            );
        }
        mgr
    }

    #[test]
    fn rebuild_deletes_and_recreates_the_table_inside_one_batch() {
        let batches = manager_with_mappings(3).rebuild_batches();

        assert_eq!(
            batches.len(),
            1,
            "a rebuild that sends the delete in a batch of its own leaves the \
             fips_gateway table absent between the two sends, so the gateway \
             has no NAT at all in that window: {batches:?}"
        );
        assert_eq!(
            batches[0][..3],
            [
                NatOp::Table(MsgType::Add),
                NatOp::Table(MsgType::Del),
                NatOp::Table(MsgType::Add),
            ],
            "the delete needs a preceding add so it always has a target, and a \
             following add to recreate the table inside the same transaction"
        );
    }

    #[test]
    fn rebuild_deletes_the_table_exactly_once_and_before_every_rule() {
        let batches = manager_with_mappings(2).rebuild_batches();
        let ops = &batches[0];

        let deletes: Vec<usize> = ops
            .iter()
            .enumerate()
            .filter(|(_, op)| matches!(op, NatOp::Table(MsgType::Del)))
            .map(|(i, _)| i)
            .collect();
        assert_eq!(deletes, vec![1], "the table is deleted once, at index 1");

        // Everything that lives in the table has to be added after the delete
        // and the recreate, or the delete would take it back out again.
        for (index, op) in ops.iter().enumerate() {
            if matches!(op, NatOp::Table(_)) {
                continue;
            }
            assert!(
                index > 2,
                "{op:?} at index {index} would be removed by the table delete"
            );
        }
    }

    #[test]
    fn rebuild_emits_a_dnat_and_an_snat_for_every_mapping() {
        let ops = manager_with_mappings(3).rebuild_batches().remove(0);

        for i in 1..=3u16 {
            assert!(ops.contains(&NatOp::Dnat(vip(i))), "no DNAT for {}", vip(i));
            assert!(ops.contains(&NatOp::Snat(vip(i))), "no SNAT for {}", vip(i));
        }
        assert!(ops.contains(&NatOp::FipsMasquerade));
        assert!(!ops.contains(&NatOp::LanMasquerade), "no port forwards");
    }

    #[test]
    fn rebuild_emits_the_lan_masquerade_once_when_port_forwards_exist() {
        let mut mgr = manager_with_mappings(1);
        mgr.port_forwards = vec![
            PortForward {
                proto: Proto::Tcp,
                listen_port: 8080,
                target: SocketAddrV6::new(Ipv6Addr::LOCALHOST, 80, 0, 0),
            },
            PortForward {
                proto: Proto::Udp,
                listen_port: 5353,
                target: SocketAddrV6::new(Ipv6Addr::LOCALHOST, 53, 0, 0),
            },
        ];

        let ops = mgr.rebuild_batches().remove(0);

        assert!(ops.contains(&NatOp::PortForward(0)));
        assert!(ops.contains(&NatOp::PortForward(1)));
        assert_eq!(
            ops.iter()
                .filter(|op| matches!(op, NatOp::LanMasquerade))
                .count(),
            1
        );
    }
}
