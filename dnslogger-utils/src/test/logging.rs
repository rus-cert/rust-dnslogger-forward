use super::super::protocols;
use super::super::capture::EventHandler;
use std::io::{self,Write};
use pcap;
use super::super::dnsxfr01::DnsXfr01Error;

pub struct TestLoggingEventHandler<'a> {
	writer: &'a mut Write,
	tcp_forward: bool,
}

impl<'a> TestLoggingEventHandler<'a> {
	pub fn new<W: Write>(writer: &'a mut W, tcp_forward: bool) -> TestLoggingEventHandler<'a> {
		TestLoggingEventHandler{
			writer: writer,
			tcp_forward: tcp_forward,
		}
	}
}

impl<'a> Write for TestLoggingEventHandler<'a> {
	fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
		self.writer.write(buf)
	}

	fn flush(&mut self) -> io::Result<()> {
		self.writer.flush()
	}
}

/* never fails */
impl<'a> EventHandler<DnsXfr01Error> for TestLoggingEventHandler<'a> {
	fn handle_link_error(&mut self, error: protocols::LinkFindIpError) {
		let _ = writeln!(self, "Couldn't find IPv4 / IPv6: {:?}", error);
	}
	fn handle_ip_error(&mut self, error: protocols::IpError, payload: &[u8]) {
		let _ = match error {
			protocols::IpError::HeaderTruncated
				=> writeln!(self, "dnslogger-forward: debug: Short packet of length {}.", payload.len()),
			protocols::IpError::HeaderLongerThanPacket{header_length, total_length}
				=> writeln!(self, "dnslogger-forward: debug: IP packet total length smaller than header, indicated total length is {}, header is {} bytes long.",
					total_length, header_length),
			protocols::IpError::PayloadTruncated{expected_length}
				=> writeln!(self, "dnslogger-forward: debug: Truncated IP packet, indicated length is {}, available is {}.",
					expected_length, payload.len()),
			_
				=> writeln!(self, "Invalid IP packet: {:?}", error),
		};
	}
	fn handle_ip_fragmented_error(&mut self, ip_info: &protocols::IpInfo) {
		let _ = writeln!(self, "IP packet is fragmented: {}", ip_info);
	}
	fn handle_ip_not_udp_error(&mut self, ip_info: &protocols::IpInfo, _: &[u8]) {
		let _ = writeln!(self, "dnslogger-forward: debug: Unexpected IP protocol {} ({} -> {}).",
			ip_info.protocol, &ip_info.source, &ip_info.destination);
	}
	fn handle_udp_error(&mut self, ip_info: &protocols::IpInfo, error: protocols::UdpError, _: &[u8]) {
		let _ = match error {
			protocols::UdpError::HeaderTruncated
				=> writeln!(self, "dnslogger-forward: debug: Truncated UDP header ({} -> {}).",
					&ip_info.source, &ip_info.destination),
			protocols::UdpError::HeaderTooShort(len)
				=> writeln!(self, "dnslogger-forward: debug: UDP total length smaller than header, indicated total length is {}, header is 8 bytes long.", len),
			protocols::UdpError::PayloadTruncated(need, have)
				=> writeln!(self, "dnslogger-forward: debug: Truncated UDP packet ({} -> {}, UDP length {}, available {}).",
					&ip_info.source, &ip_info.destination, need, have),
			_ => writeln!(self, "Invalid UDP packet {}: {:?}", ip_info, error),
		};
	}
	fn handle_dns_too_short(&mut self, _: &protocols::IpInfo, _: &protocols::UdpInfo, payload: &[u8]) {
		let _ = writeln!(self, "dnslogger-forward: debug: Truncated DNS packet (length {}).", payload.len());
	}
	fn handle_dns_is_query(&mut self, ip_info: &protocols::IpInfo, _: &protocols::UdpInfo, _: &protocols::DnsInfo) {
		let _ = writeln!(self, "dnslogger-forward: debug: Dropping question packet ({} -> {}).", &ip_info.source, &ip_info.destination);
	}
	fn handle_dns_is_not_authoritative(&mut self, ip_info: &protocols::IpInfo, _: &protocols::UdpInfo, _: &protocols::DnsInfo) {
		let _ = writeln!(self, "dnslogger-forward: debug: Dropping non-authoritative DNS packet ({} -> {}).", &ip_info.source, &ip_info.destination);
	}
	fn handle_dns_has_no_answers(&mut self, ip_info: &protocols::IpInfo, _: &protocols::UdpInfo, _: &protocols::DnsInfo) {
		let _ = writeln!(self, "dnslogger-forward: debug: Dropping packet without answers ({} -> {}).", &ip_info.source, &ip_info.destination);
	}
	fn handle_non_fatal_forward_error(&mut self, ip_info: &protocols::IpInfo, _: &protocols::UdpInfo, _: &protocols::DnsInfo, dns_data: &[u8], error: &DnsXfr01Error) {
		let _ = match *error {
			DnsXfr01Error::BufferTooSmall =>
				writeln!(self, "dnslogger-forward: debug: Dropping overlong packet ({} -> {}, {} bytes).",
					&ip_info.source, &ip_info.destination, dns_data.len()),
			_ => 
				writeln!(self, "Failed forwarding DNS packet: {}", error)
		};
	}
	fn handle_success(&mut self, _: &protocols::IpInfo, _: &protocols::UdpInfo, _: &protocols::DnsInfo, dns_data: &[u8]) {
		if !self.tcp_forward {
			/* only shown for UDP */
			let _ = writeln!(self, "dnslogger-forward: debug: Forwarded {} bytes.", dns_data.len() + 12);
		}
	}
	fn show_stat(&mut self, _: &pcap::Stat) {
	}
}
