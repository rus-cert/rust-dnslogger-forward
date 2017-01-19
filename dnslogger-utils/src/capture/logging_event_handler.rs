use super::super::protocols;
use super::{EventHandler,ForwardError};
use std::boxed::Box;
use std::io;
use std::io::Write;
use pcap;



pub struct LoggingEventHandler<'a> {
	writer: Box<Write+'a>,
	level: u64,
}

impl<'a> LoggingEventHandler<'a> {
	pub fn new<W: Write+'a>(writer: W, level: u64) -> LoggingEventHandler<'a> {
		LoggingEventHandler{
			writer: Box::new(writer),
			level: level,
		}
	}

	fn show_debug(&self) -> bool {
		self.level >= 2
	}

	fn show_protocol_errors(&self) -> bool {
		self.level >= 1
	}
}

impl<'a> Write for LoggingEventHandler<'a> {
	fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
		self.writer.write(buf)
	}

	fn flush(&mut self) -> io::Result<()> {
		self.writer.flush()
	}
}

/* never fails */
impl<'a, E: ForwardError> EventHandler<E> for LoggingEventHandler<'a> {
	fn handle_link_error(&mut self, error: protocols::LinkFindIpError) {
		if self.show_debug() {
			let _ = writeln!(self, "Couldn't find IPv4 / IPv6: {:?}", error);
		}
	}
	fn handle_ip_error(&mut self, error: protocols::IpError, _: &[u8]) {
		if self.show_protocol_errors() {
			let _ = writeln!(self, "Invalid IP packet: {:?}", error);
		}
	}
	fn handle_ip_fragmented_error(&mut self, ip_info: &protocols::IpInfo) {
		if self.show_debug() {
			let _ = writeln!(self, "IP packet is fragmented: {}", ip_info);
		}
	}
	fn handle_ip_not_udp_error(&mut self, ip_info: &protocols::IpInfo, _: &[u8]) {
		if self.show_debug() {
			let _ = writeln!(self, "IP packet is not UDP: {}", ip_info);
		}
	}
	fn handle_udp_error(&mut self, ip_info: &protocols::IpInfo, error: protocols::UdpError, _: &[u8]) {
		if self.show_protocol_errors() {
			let _ = writeln!(self, "Invalid UDP packet {}: {:?}", ip_info, error);
		}
	}
	fn handle_dns_too_short(&mut self, ip_info: &protocols::IpInfo, udp_info: &protocols::UdpInfo, _: &[u8]) {
		if self.show_protocol_errors() {
			let _ = writeln!(self, "Invalid DNS packet {}: too short", protocols::udp::IpUdpInfo(&ip_info, &udp_info));
		}
	}
	fn handle_dns_is_query(&mut self, ip_info: &protocols::IpInfo, udp_info: &protocols::UdpInfo, dns_info: &protocols::DnsInfo) {
		if self.show_debug() {
			let _ = writeln!(self, "DNS packet {}: {:?}: is a query", protocols::udp::IpUdpInfo(&ip_info, &udp_info), dns_info);
		}
	}
	fn handle_dns_is_not_authoritative(&mut self, ip_info: &protocols::IpInfo, udp_info: &protocols::UdpInfo, dns_info: &protocols::DnsInfo) {
		if self.show_debug() {
			let _ = writeln!(self, "DNS packet {}: {:?}: is not authoritative", protocols::udp::IpUdpInfo(&ip_info, &udp_info), dns_info);
		}
	}
	fn handle_dns_has_no_answers(&mut self, ip_info: &protocols::IpInfo, udp_info: &protocols::UdpInfo, dns_info: &protocols::DnsInfo) {
		if self.show_debug() {
			let _ = writeln!(self, "DNS packet {}: {:?}: has no answers", protocols::udp::IpUdpInfo(&ip_info, &udp_info), dns_info);
		}
	}
	fn handle_non_fatal_forward_error(&mut self, _: &protocols::IpInfo, _: &protocols::UdpInfo, _: &protocols::DnsInfo, _: &[u8], error: &E) {
		if self.show_debug() {
			let _ = writeln!(self, "Failed forwarding DNS packet: {}", error);
		}
	}
	fn handle_success(&mut self, ip_info: &protocols::IpInfo, udp_info: &protocols::UdpInfo, dns_info: &protocols::DnsInfo, /* dns_data */ _: &[u8]) {
		if self.show_debug() {
			let _ = writeln!(self, "Successfully forwared DNS packet {}: {:?}", protocols::udp::IpUdpInfo(&ip_info, &udp_info), dns_info);
		}
	}
	fn show_stat(&mut self, stat: &pcap::Stat) {
		println!("Capture stats: {:?}", stat);
	}
}
