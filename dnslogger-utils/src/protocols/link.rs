use pcap;
use super::IpFamily;

#[allow(non_camel_case_types)]
#[repr(i32)]
#[derive(Clone,Copy,PartialEq,Eq,PartialOrd,Ord,Hash,Debug)]
pub enum Linktype {
	DLT_EN10MB = 1,
	DLT_LINUX_SLL = 113,
	DLT_IPV4 = 228,
	DLT_IPV6 = 229,
}

#[derive(Clone,Copy,PartialEq,Eq,PartialOrd,Ord,Hash,Debug)]
pub enum LinkFindIpError {
	UnexpectedEndOfData,
	UnknownEtherType(u16),
}

impl Linktype {
	pub fn find_ip_layer<'a>(&self, payload: &'a [u8]) -> Result<(IpFamily, &'a [u8]), LinkFindIpError> {
		let get_ethertype = |offset: usize| -> Result<u16, LinkFindIpError> {
			if offset + 1 >= payload.len() { return Err(LinkFindIpError::UnexpectedEndOfData); }
			Ok((payload[offset] as u16) << 8 | (payload[offset + 1] as u16))
		};

		/* position of (next) ethertype field in payload */
		let mut pos = match *self {
			Linktype::DLT_EN10MB => 12usize,
			Linktype::DLT_LINUX_SLL => 14usize,
			Linktype::DLT_IPV4 => return Ok((IpFamily::IPv4, payload)),
			Linktype::DLT_IPV6 => return Ok((IpFamily::IPv6, payload)),
		};

		loop {
			match try!(get_ethertype(pos)) {
				0x0800 => return Ok((IpFamily::IPv4, &payload[pos+2..])),
				0x86DD => return Ok((IpFamily::IPv6, &payload[pos+2..])),
				0x8100 | 0x9100 => { pos += 4 }, /* IEEE_802.1Q */
				ethertype => return Err(LinkFindIpError::UnknownEtherType(ethertype)),
			}
		}
	}

	pub fn try_from(lt: &pcap::Linktype) -> Option<Linktype> {
		const DLT_EN10MB: i32 = Linktype::DLT_EN10MB as i32;
		const DLT_LINUX_SLL: i32 = Linktype::DLT_LINUX_SLL as i32;
		const DLT_IPV4: i32 = Linktype::DLT_IPV4 as i32;
		const DLT_IPV6: i32 = Linktype::DLT_IPV6 as i32;
		match lt.0 {
			DLT_EN10MB => Some(Linktype::DLT_EN10MB),
			DLT_LINUX_SLL => Some(Linktype::DLT_LINUX_SLL),
			DLT_IPV4 => Some(Linktype::DLT_IPV4),
			DLT_IPV6 => Some(Linktype::DLT_IPV6),
			_ => None,
		}
	}
}
