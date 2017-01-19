use byteorder::{BigEndian,ByteOrder};

#[derive(Clone,Copy,PartialEq,Eq,PartialOrd,Ord,Hash,Debug)]
pub enum DnsType {
	Query,
	Response,
}

pub mod opcode {
	pub const QUERY: u8 = 0;
	pub const IQUERY: u8 = 1;
	pub const STATUS: u8 = 2;
}

pub mod rcode {
	pub const SUCCESS: u8 = 0;
	pub const FORMAT_ERROR: u8 = 1;
	pub const SERVER_FAILURE: u8 = 2;
	pub const NAME_ERROR: u8 = 3;
	pub const NOT_IMPLEMENTED: u8 = 4;
	pub const REFUSED: u8 = 5;
}

#[derive(Clone,PartialEq,Eq,PartialOrd,Ord,Hash,Debug)]
pub struct DnsInfo {
	pub id: u16,
	/* packed into 16 bits */
	pub qr: DnsType,
	pub opcode: u8,
	pub authoritative_answer: bool,
	pub truncation: bool,
	pub recursion_desired: bool,
	pub recursion_available: bool,
	pub rcode: u8,
	/* end packed 16 bits */
	pub qdcount: u16,
	pub ancount: u16,
	pub nscount: u16,
	pub arcount: u16,
}

/* only fails if payload too short */
pub fn dns_info(udp_payload: &[u8]) -> Option<DnsInfo> {
	if udp_payload.len() < 12 { return None; }
	let packed = BigEndian::read_u16(&udp_payload[2..4]);
	Some(DnsInfo{
		id: BigEndian::read_u16(&udp_payload[0..2]),
		qr: if 0 == packed & 0x8000 { DnsType::Query } else { DnsType::Response },
		opcode: ((packed >> 11) & 0xf) as u8,
		authoritative_answer: 0 != packed & 0x0400,
		truncation: 0 != packed & 0x0200,
		recursion_desired: 0 != packed & 0x0100,
		recursion_available: 0 != packed & 0x0080,
		rcode: (packed & 0xf) as u8,
		qdcount: BigEndian::read_u16(&udp_payload[4..6]),
		ancount: BigEndian::read_u16(&udp_payload[6..8]),
		nscount: BigEndian::read_u16(&udp_payload[8..10]),
		arcount: BigEndian::read_u16(&udp_payload[10..12]),
	})
}

#[derive(Clone,Copy,PartialEq,Eq,PartialOrd,Ord,Hash,Debug)]
pub enum DnsParseError {
	InvalidLengthOctetInName,
	NameTooLong,
	InvalidCompressedName,
	UnexpectedEndOfData, /* might be expected with partial answer */
}

fn name_length(buf: &[u8]) -> Result<usize, DnsParseError> {
	let mut pos = 0usize;
	while pos < buf.len() {
		if 0 == buf[pos] {
			/* empty label terminating name */
			return Ok(pos + 1);
		} else if buf[pos] & 0xc0 == 0xc0 {
			/* compressed name, terminated here */
			if pos + 1 >= buf.len() { break; }
			let new_pos = (((buf[pos] & 0x3f) as usize) << 8) | buf[pos+1] as usize;
			if new_pos >= pos { return Err(DnsParseError::InvalidCompressedName); }
			return Ok(pos + 2);
		} else if buf[pos] < 64 {
			/* normal label */
			pos += 1 + (buf[pos] as usize);
			if pos >= 255 { return Err(DnsParseError::NameTooLong) }
		} else {
			/* reserved for future use */
			return Err(DnsParseError::InvalidLengthOctetInName);
		}
	}
	Err(DnsParseError::UnexpectedEndOfData)
}

fn question_length(buf: &[u8]) -> Result<usize, DnsParseError> {
	let name_len = try!(name_length(buf));
	// skip QTYPE: u16 and QCLASS: u16
	if buf.len() < name_len + 4 { return Err(DnsParseError::UnexpectedEndOfData); }
	Ok(name_len + 4)
}

fn rr_length(buf: &[u8]) -> Result<usize, DnsParseError> {
	let name_len = try!(name_length(buf));
	// skip TYPE: u16, CLASS: u16, TTL: u32; parse RDLENGTH: u16
	if buf.len() < name_len + 10 { return Err(DnsParseError::UnexpectedEndOfData); }
	let rdlength = BigEndian::read_u16(&buf[name_len + 8..name_len + 10]) as usize;
	if buf.len() < name_len + 10 + rdlength { return Err(DnsParseError::UnexpectedEndOfData); }
	Ok(name_len + 10 + rdlength)
}

pub struct DnsPacketSections {
	/* if not truncated contains end (last + 1) offset of data in udp payload */
	pub question: Option<usize>,
	pub answer: Option<usize>,
	pub authority: Option<usize>,
	pub additional: Option<usize>,
}

pub fn dns_sections(udp_payload: &[u8], info: &DnsInfo) -> Result<DnsPacketSections, DnsParseError> {
	let mut pos = 12;
	let mut result = DnsPacketSections{
		question: None,
		answer: None,
		authority: None,
		additional: None,
	};
	/* question */
	for _ in 0..info.qdcount {
		pos += match question_length(&udp_payload[pos..]) {
			Ok(l) => l,
			Err(DnsParseError::UnexpectedEndOfData) if info.truncation => return Ok(result),
			Err(e) => return Err(e),
		}
	}
	result.question = Some(pos);

	/* answer */
	for _ in 0..info.qdcount {
		pos += match rr_length(&udp_payload[pos..]) {
			Ok(l) => l,
			Err(DnsParseError::UnexpectedEndOfData) if info.truncation => return Ok(result),
			Err(e) => return Err(e),
		}
	}
	result.answer = Some(pos);

	/* authority */
	for _ in 0..info.qdcount {
		pos += match rr_length(&udp_payload[pos..]) {
			Ok(l) => l,
			Err(DnsParseError::UnexpectedEndOfData) if info.truncation => return Ok(result),
			Err(e) => return Err(e),
		}
	}
	result.authority = Some(pos);

	/* additional */
	for _ in 0..info.qdcount {
		pos += match rr_length(&udp_payload[pos..]) {
			Ok(l) => l,
			Err(DnsParseError::UnexpectedEndOfData) if info.truncation => return Ok(result),
			Err(e) => return Err(e),
		}
	}
	result.additional = Some(pos);

	Ok(result)
}
