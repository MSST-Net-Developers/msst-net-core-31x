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
    /// Set when the packet is one fragment of a larger datagram (IPv4
    /// MF/offset, IPv6 Fragment header).  `None` for whole packets,
    /// including IPv6 atomic fragments (offset 0, no more fragments).
    pub fragment: Option<Fragment>,
}

impl ParsedPacket {
    /// A fragment other than the first: it carries no transport header, so
    /// `src_port`/`dst_port` are 0 and `proto` alone can't be evaluated.
    /// It follows the verdict of its first fragment (see
    /// [`crate::packet::fragment`]).
    pub fn is_later_fragment(&self) -> bool {
        self.fragment.is_some_and(|f| f.offset != 0)
    }
}

/// Fragmentation fields of a fragmented packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fragment {
    /// Identification (16 bits for IPv4, 32 bits for IPv6).
    pub id: u32,
    /// Fragment offset in 8-byte units; 0 for the first fragment.
    pub offset: u16,
    /// More fragments follow.
    pub more: bool,
}