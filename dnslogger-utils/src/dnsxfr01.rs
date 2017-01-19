use std::net::{UdpSocket,TcpStream,SocketAddr,IpAddr};
use std;
use std::fmt;
use super::capture::{Forwarder,ForwardError};
use super::protocols;
use byteorder::{BigEndian,ByteOrder};

const SIGNATURE : &'static str = "DNSXFR01";
static ZERO_ADDR : [u8; 4] = [0u8; 4];

#[derive(Debug)]
pub enum DnsXfr01Error {
	BufferTooSmall,
	IoError(std::io::Error),
}
impl fmt::Display for DnsXfr01Error {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		fmt::Debug::fmt(self, f)
	}
}
impl std::error::Error for DnsXfr01Error {
	fn description(&self) -> &str {
		match *self {
			DnsXfr01Error::BufferTooSmall => "buffer too small",
			DnsXfr01Error::IoError(ref e) => e.description(),
		}
	}
	fn cause(&self) -> Option<&std::error::Error> {
		match *self {
			DnsXfr01Error::BufferTooSmall => None,
			DnsXfr01Error::IoError(ref e) => Some(e),
		}
	}
}
impl ForwardError for DnsXfr01Error {
	fn fatal(&self) -> bool {
		match *self {
			DnsXfr01Error::BufferTooSmall => false,
			DnsXfr01Error::IoError(_) => true,
		}
	}
}

pub fn pack_buffer<'a, 'b>(buf: &'a mut [u8], ip_info: &protocols::IpInfo, dns_info: &protocols::DnsInfo, payload: &'b [u8]) -> Result<&'a [u8], DnsXfr01Error> {
	/* C struct definition; the payload isn't fixed length, just limited */
	// typedef struct
	// {
	//   char signature[8];
	//   ipv4_t nameserver; /* in network byte order */
	//   char payload[512];
	// } forward_t;

	if payload.len() + 12 > buf.len() {
		return Err(DnsXfr01Error::BufferTooSmall);
	}

	// only send IPv4 nameserver for authoritative answers; sending IPv6
	// is not supported
	let nameserver = if dns_info.authoritative_answer {
		match ip_info.source {
			IpAddr::V4(a) => Some(a),
			_ => None,
		}
	} else {
		None
	};

	let nameserver_bytes = match nameserver {
		Some(ref addr) => addr.octets(),
		None => ZERO_ADDR,
	};
	buf[0..8].copy_from_slice(SIGNATURE.as_bytes());
	buf[8..12].copy_from_slice(&nameserver_bytes[..]);
	buf[12..payload.len() + 12].copy_from_slice(payload);

	return Ok(&buf[0..payload.len() + 12]);
}

pub struct UdpForwarder {
	sock: UdpSocket,
	target: SocketAddr,
	buf: Vec<u8>,
}

impl UdpForwarder {
	pub fn new(sock: UdpSocket, target: SocketAddr, max_message_size: usize) -> UdpForwarder {
		UdpForwarder{
			sock: sock,
			target: target,
			buf: vec![0u8; max_message_size+12], // 12 byte header
		}
	}
}

impl Forwarder for UdpForwarder {
	type Error = DnsXfr01Error;

	fn forward(&mut self, ip_info: &protocols::IpInfo, _: &protocols::UdpInfo, dns_info: &protocols::DnsInfo, dns_data: &[u8]) -> Result<(), DnsXfr01Error> {
		try_wrap_err!(DnsXfr01Error::IoError, self.sock.send_to(
			try!(pack_buffer(&mut self.buf, ip_info, dns_info, dns_data)),
			self.target,
		));
		Ok(())
	}
}

pub struct TcpForwarder {
	sock: TcpStream,
	buf: Vec<u8>,
}

impl TcpForwarder {
	pub fn new(sock: TcpStream, max_message_size: usize) -> TcpForwarder {
		TcpForwarder{
			sock: sock,
			buf: vec![0u8; max_message_size+14], // 14 byte header
		}
	}
}

impl Forwarder for TcpForwarder {
	type Error = DnsXfr01Error;

	fn forward(&mut self, ip_info: &protocols::IpInfo, _: &protocols::UdpInfo, dns_info: &protocols::DnsInfo, dns_data: &[u8]) -> Result<(), DnsXfr01Error> {
		use std::io::Write;

		// prepend msglen as big-endian uint16
		let msglen = try!(pack_buffer(&mut self.buf[2..], ip_info, dns_info, dns_data)).len();
		BigEndian::write_u16(&mut self.buf[0..2], msglen as u16);

		try_wrap_err!(DnsXfr01Error::IoError, self.sock.write_all(&self.buf[0..msglen+2]));
		Ok(())
	}
}
