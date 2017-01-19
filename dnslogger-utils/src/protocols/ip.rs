use std::net::{IpAddr,Ipv4Addr,Ipv6Addr};
use std::fmt;

use byteorder::{BigEndian,ByteOrder};
use csum;

#[derive(Clone,Copy,PartialEq,Eq,PartialOrd,Ord,Hash,Debug)]
pub enum IpFamily {
	IPv4,
	IPv6,
}

#[derive(Clone,PartialEq,Eq,PartialOrd,Ord,Hash,Debug)]
pub struct IpInfo {
	pub source : IpAddr,
	pub destination: IpAddr,
	pub fragment: Option<(usize, u32, bool)>, /* offset, identification (IPv4: only 16-bits are used), more */
	pub protocol: u8, /* protocol of returned payload (IPv6: first "unknown" NextHeader) */
	pub jumbo: bool, /* IPv6 only */
}

impl IpInfo {
	pub fn fmt_ports(&self, f: &mut fmt::Formatter, ports: (u16, u16)) -> fmt::Result {
		use std::string::String;
		write!(f, "[{}]:{} -> [{}]:{}{}{}: protocol {:X}",
			self.source,
			ports.0,
			self.destination,
			ports.1,
			if self.jumbo { ": jumbo" } else { "" },
			match self.fragment {
				None => String::new(),
				Some((offset, _, true)) => format!(": fragment offset {}", offset),
				Some((offset, _, false)) => format!(": last fragment offset {}", offset),
			},
			self.protocol,
		)
	}
}

impl fmt::Display for IpInfo {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		use std::string::String;
		write!(f, "{} -> {}{}{}: protocol {:X}",
			self.source,
			self.destination,
			if self.jumbo { ": jumbo" } else { "" },
			match self.fragment {
				None => String::new(),
				Some((offset, _, true)) => format!(": fragment offset {}", offset),
				Some((offset, _, false)) => format!(": last fragment offset {}", offset),
			},
			self.protocol,
		)
	}
}

#[derive(Clone,Copy,PartialEq,Eq,PartialOrd,Ord,Hash,Debug)]
pub enum IpError {
	HeaderTruncated,
	VersionMismatch,
	HeaderTooShort, /* IPv4 only */
	HeaderLongerThanPacket{header_length: usize, total_length: usize}, /* IPv4 only */
	ExtensionHeaderLongerThanPacket, /* IPv6 only */
	HeaderChecksumMismatch,
	InvalidExtensionHeader, /* IPv6 only */
	FragmentOversize, /* offset + size too big */
	PayloadTruncated{expected_length: usize},
}

fn find_jumbo_payload_option(hop_by_hop_header: &[u8]) -> Option<usize> {
	let mut off : usize = 2;
	while off < hop_by_hop_header.len() {
		match hop_by_hop_header[off] {
			0 => off += 1,
			0xC2 => {
				if off % 4 != 2 { return None; } /* wrong alignment */
				if off + 6 > hop_by_hop_header.len() { return None; } /* truncated */
				if hop_by_hop_header[off+1] != 4 { return None; } /* always 4 bytes content */
				let payload_length = BigEndian::read_u32(&hop_by_hop_header[off+2..off+6]) as usize;
				if payload_length <= 65535 { return None; } /* invalid: not a jumbo payload */
				return Some(payload_length);
			}
			_ => {
				if off + 1 > hop_by_hop_header.len() { return None; } /* truncated */
				off += 2 + (hop_by_hop_header[off+1] as usize); /* skip option */
			}
		}
	}
	None
}

impl IpFamily {
	pub fn pseudo_header_checksum_with<C: csum::traits::CSum>(self, ip_payload: &[u8], transport_size: usize, csum: C) -> C {
		use std::mem::transmute;
		let transport_size_bytes : [u8; 4] = unsafe { transmute((transport_size as u32).to_be()) };
		match self {
			IpFamily::IPv4 => {
				let protocol_bytes : [u8; 2] = [ 0, ip_payload[9] ];
				csum.add(&ip_payload[12..20]).add(&protocol_bytes[..]).add(&transport_size_bytes[..])
			},
			IpFamily::IPv6 => {
				let next_header_bytes : [u8; 2] = [ 0, ip_payload[6] ];
				csum.add(&ip_payload[8..40]).add(&transport_size_bytes[..]).add(&next_header_bytes[..])
			}
		}
	}

	pub fn pseudo_header_checksum(self, ip_payload: &[u8], transport_size: usize, csum: csum::CSum) -> csum::CSum {
		self.pseudo_header_checksum_with(ip_payload, transport_size, csum)
	}

	pub fn check_packet<'a>(self, mut ip_payload: &'a [u8]) -> Result<(IpInfo, &'a [u8]), IpError> {
		match self {
			IpFamily::IPv4 => {
				if ip_payload.len() < 20 { return Err(IpError::HeaderTruncated); }
				if ip_payload[0] & 0xf0 != 0x40 { return Err(IpError::VersionMismatch); }
				let header_length = (ip_payload[0] & 0x0f) as usize * 4;
				if header_length < 20 { return Err(IpError::HeaderTooShort); }
				let total_length = BigEndian::read_u16(&ip_payload[2..4]) as usize;
				if header_length > total_length { return Err(IpError::HeaderLongerThanPacket{
					header_length: header_length,
					total_length: total_length,
				}); }
				if header_length > ip_payload.len() { return Err(IpError::HeaderTruncated); }
				if 0 != !csum::CSum::new().add(&ip_payload[0..header_length]).result() {
					return Err(IpError::HeaderChecksumMismatch);
				}
				let fragment_spec = BigEndian::read_u16(&ip_payload[6..8]);
				let fragment_offset = (fragment_spec & 0x1fff) as usize * 8;
				let fragment_id = BigEndian::read_u16(&ip_payload[4..6]) as u32;
				// let flag_df = 0 != fragment_spec & 0x4000;
				let flag_mf = 0 != fragment_spec & 0x2000;
				if fragment_offset + total_length > 0xffff { return Err(IpError::FragmentOversize); }
				if total_length > ip_payload.len() { return Err(IpError::PayloadTruncated{expected_length: total_length}); }

				Ok((IpInfo{
					source: IpAddr::V4(Ipv4Addr::from(array_ref!(ip_payload, 12, 4).clone())),
					destination: IpAddr::V4(Ipv4Addr::from(array_ref!(ip_payload, 16, 4).clone())),
					fragment: if 0 != fragment_offset || flag_mf { Some((fragment_offset, fragment_id, flag_mf)) } else { None },
					protocol: ip_payload[9],
					jumbo: false,
				}, &ip_payload[header_length..total_length]))
			},
			IpFamily::IPv6 => {
				if ip_payload.len() < 40 { return Err(IpError::HeaderTruncated); }
				if ip_payload[0] & 0xf0 != 0x60 { return Err(IpError::VersionMismatch); }
				if 0 != !csum::CSum::new().add(&ip_payload[0..40]).result() {
					return Err(IpError::HeaderChecksumMismatch);
				}
				let mut payload_length = BigEndian::read_u16(&ip_payload[4..6]) as usize;
				let mut next_header = ip_payload[6];
				let mut payload_offset : usize = 40;
				let mut jumbo = false;

				// Hop-by-hop extension header must come first if present
				if 0 == next_header {
					if payload_offset + 8 > ip_payload.len() { return Err(IpError::ExtensionHeaderLongerThanPacket); }
					next_header = ip_payload[payload_offset];
					let hop_by_hop_length = 8 + 8*(ip_payload[payload_offset+1] as usize);
					if payload_offset + hop_by_hop_length > ip_payload.len() { return Err(IpError::ExtensionHeaderLongerThanPacket); }
					let hop_by_hop_header = &ip_payload[payload_offset..][..hop_by_hop_length];
					payload_offset += hop_by_hop_length;

					if 0 == payload_length {
						payload_length = match find_jumbo_payload_option(hop_by_hop_header) {
							Some(res) => res,
							None => return Err(IpError::PayloadTruncated{expected_length: payload_length}),
						};
						jumbo = true;
					}
				}
				if payload_length > ip_payload.len() - 40 { return Err(IpError::PayloadTruncated{expected_length: payload_length}); }
				ip_payload = &ip_payload[0..payload_length+40];

				let mut fragment: Option<(usize, u32, bool)> = None;
				loop {
					/* can't contain a valid extension header; simply return the current next header as protocol */
					if payload_offset + 8 >= ip_payload.len() { break; }

					match next_header {
						0 => {
							/* Hop-by-hop: should have been the first extension */
							return Err(IpError::InvalidExtensionHeader);
						},
						43 => {
							/* Routing: skip */
							next_header = ip_payload[payload_offset];
							payload_offset += 8 + 8 * (ip_payload[payload_offset+1] as usize);
						},
						44 => {
							/* Fragment */
							if jumbo { return Err(IpError::InvalidExtensionHeader); }
							next_header = ip_payload[payload_offset];

							let fragment_spec = BigEndian::read_u16(&ip_payload[payload_offset+2..][..2]);
							let fragment_offset = (fragment_spec & 0xfff8) as usize;
							let fragment_id = BigEndian::read_u32(&ip_payload[payload_offset+4..][..4]);
							let flag_mf = 0 != fragment_spec & 0x0001;
							if flag_mf && 0 != (payload_length % 8) { return Err(IpError::InvalidExtensionHeader); }

							payload_offset += 8;
							if fragment_offset + payload_length - payload_offset > 0xffff - 40 { return Err(IpError::FragmentOversize); }

							fragment = Some((fragment_offset, fragment_id, flag_mf));
							break; /* not parsing fragment content */
						},
						59 => {
							/* No Next Header */
							break;
						},
						60 => {
							/* Destination Options: skip */
							next_header = ip_payload[payload_offset];
							payload_offset += 8 + 8 * (ip_payload[payload_offset+1] as usize);
						},
						_ => {
							/* unknown next header */
							break;
						},
					}
				}

				Ok((IpInfo{
					source: IpAddr::V6(Ipv6Addr::from(array_ref!(ip_payload, 8, 16).clone())),
					destination: IpAddr::V6(Ipv6Addr::from(array_ref!(ip_payload, 24, 16).clone())),
					fragment: fragment,
					protocol: next_header,
					jumbo: jumbo,
				}, &ip_payload[payload_offset..]))
			}
		}
	}
}
