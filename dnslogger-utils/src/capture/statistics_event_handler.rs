use super::super::protocols;
use super::{EventHandler,ForwardError};
use pcap;

#[derive(Default,Clone,PartialEq,Eq,PartialOrd,Ord,Hash,Debug)]
pub struct StatisticsEventHandler {
	count_link_error: u64,
	count_ip_error: u64,
	count_ip_fragmented_error: u64,
	count_ip_not_udp_error: u64,
	count_udp_error: u64,
	count_dns_too_short: u64,
	count_dns_is_query: u64,
	count_dns_is_not_authoritative: u64,
	count_dns_has_no_answers: u64,
	count_forward_errors: u64,
	count_fatal_forward_errors: u64,
	count_success: u64,
}

impl StatisticsEventHandler {
	pub fn new() -> StatisticsEventHandler {
		Default::default()
	}
}

/* never fails */
#[allow(unused_variables)]
impl<E: ForwardError> EventHandler<E> for StatisticsEventHandler {
	fn handle_link_error(&mut self, error: protocols::LinkFindIpError) {
		self.count_link_error += 1;
	}
	fn handle_ip_error(&mut self, error: protocols::IpError, payload: &[u8]) {
		self.count_ip_error += 1;
	}
	fn handle_ip_fragmented_error(&mut self, ip_info: &protocols::IpInfo) {
		self.count_ip_fragmented_error += 1;
	}
	fn handle_ip_not_udp_error(&mut self, ip_info: &protocols::IpInfo, payload: &[u8]) {
		self.count_ip_not_udp_error += 1;
	}
	fn handle_udp_error(&mut self, ip_info: &protocols::IpInfo, error: protocols::UdpError, payload: &[u8]) {
		self.count_udp_error += 1;
	}
	fn handle_dns_too_short(&mut self, ip_info: &protocols::IpInfo, udp_info: &protocols::UdpInfo, payload: &[u8]) {
		self.count_dns_too_short += 1;
	}
	fn handle_dns_is_query(&mut self, ip_info: &protocols::IpInfo, udp_info: &protocols::UdpInfo, dns_info: &protocols::DnsInfo) {
		self.count_dns_is_query += 1;
	}
	fn handle_dns_is_not_authoritative(&mut self, ip_info: &protocols::IpInfo, udp_info: &protocols::UdpInfo, dns_info: &protocols::DnsInfo) {
		self.count_dns_is_not_authoritative += 1;
	}
	fn handle_dns_has_no_answers(&mut self, ip_info: &protocols::IpInfo, udp_info: &protocols::UdpInfo, dns_info: &protocols::DnsInfo) {
		self.count_dns_has_no_answers += 1;
	}
	fn handle_non_fatal_forward_error(&mut self, ip_info: &protocols::IpInfo, udp_info: &protocols::UdpInfo, dns_info: &protocols::DnsInfo, dns_data: &[u8], error: &E) {
		if error.fatal() {
			self.count_fatal_forward_errors += 1;
		} else {
			self.count_forward_errors += 1;
		}
	}
	fn handle_success(&mut self, ip_info: &protocols::IpInfo, udp_info: &protocols::UdpInfo, dns_info: &protocols::DnsInfo, dns_data: &[u8]) {
		self.count_success += 1;
	}
	fn show_stat(&mut self, stat: &pcap::Stat) {
		println!("Packet handling stats: {:?}", self);
	}
}
