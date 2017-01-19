use super::ip;
use std::fmt;

use byteorder::{BigEndian,ByteOrder};
use csum;

#[derive(Clone,Copy,PartialEq,Eq,PartialOrd,Ord,Hash,Debug)]
pub struct UdpInfo {
	source_port: u16,
	destination_port: u16,
}

pub struct IpUdpInfo<'a>(pub &'a ip::IpInfo, pub &'a UdpInfo);
impl<'a> fmt::Display for IpUdpInfo<'a> {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		self.0.fmt_ports(f, (self.1.source_port, self.1.destination_port))
	}
}

#[derive(Clone,Copy,PartialEq,Eq,PartialOrd,Ord,Hash,Debug)]
pub enum UdpError {
	HeaderTruncated,
	HeaderTooShort(usize),
	ChecksumMismatch,
	PayloadTruncated(usize, usize),
}

pub fn check_udp<'a>(ip_family: ip::IpFamily, ip_info: &ip::IpInfo, ip_payload: &[u8], mut udp_payload: &'a [u8]) -> Result<(UdpInfo, &'a [u8]), UdpError> {
	if udp_payload.len() < 8 { return Err(UdpError::HeaderTruncated); }
	let udp_length = BigEndian::read_u16(&udp_payload[4..6]);
	if 0 == udp_length {
		if !ip_info.jumbo { return Err(UdpError::HeaderTooShort(udp_length as usize)); }
	} else if udp_length < 8 {
		return Err(UdpError::HeaderTooShort(udp_length as usize));
	} else if udp_length as usize > udp_payload.len() {
		return Err(UdpError::PayloadTruncated(udp_length as usize, udp_payload.len()));
	} else {
		udp_payload = &udp_payload[0..udp_length as usize];
	}
	if ip::IpFamily::IPv4 != ip_family || 0 != BigEndian::read_u16(&udp_payload[6..8]) {
		if 0 != !ip_family.pseudo_header_checksum(ip_payload, udp_payload.len(), csum::CSum::new()).add(udp_payload).result() {
			return Err(UdpError::ChecksumMismatch);
		}
	}
	Ok((UdpInfo{
			source_port: BigEndian::read_u16(&udp_payload[0..2]),
			destination_port: BigEndian::read_u16(&udp_payload[2..4]),
	}, &udp_payload[8..]))
}
