//! Parsed packet descriptor — the output of IP/transport header parsing.
//!
//! The Core runtime parses raw IP bytes into this struct, then passes it to
//! the pipeline.  Parsing is separated from evaluation so the pipeline itself
//! has no dependency on `etherparse` or any packet parsing library.

use std::net::IpAddr;

/// The transport protocol extracted from the IP header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TransportProtocol {
    Tcp,
    Udp,
    Icmp,
    Other(u8),
}

impl TransportProtocol {
    /// Returns the IP protocol number.
    pub fn number(self) -> u8 {
        match self {
            Self::Tcp => 6,
            Self::Udp => 17,
            Self::Icmp => 1,
            Self::Other(n) => n,
        }
    }
}

/// A parsed inbound IP packet descriptor.
///
/// Contains everything the pipeline needs to evaluate ACL rules — no raw
/// bytes, no I/O handles.
#[derive(Debug, Clone)]
pub struct ParsedPacket {
    /// Source IP address (from the IP header).
    pub src_ip: IpAddr,
    /// Destination IP address (from the IP header).
    pub dst_ip: IpAddr,
    /// Transport protocol (TCP, UDP, ICMP, or other).
    pub proto: TransportProtocol,
    /// Source port (0 for non-TCP/UDP).
    pub src_port: u16,
    /// Destination port (0 for non-TCP/UDP).
    pub dst_port: u16,
    /// Whether this is an ICMP echo request (ping).
    pub is_icmp_echo_request: bool,
}