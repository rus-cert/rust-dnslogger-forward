use super::super::protocols;
use super::{EventHandler,ForwardError};

use std::marker::PhantomData;

use pcap;

pub struct CombinedEventHandler<E: ForwardError, A: EventHandler<E>, B: EventHandler<E>> {
	pub first: A,
	pub second: B,
	pub _marker: PhantomData<E>,
}

impl<E: ForwardError, A: EventHandler<E>, B: EventHandler<E>> EventHandler<E> for CombinedEventHandler<E, A, B> {
	fn handle_link_error(&mut self, error: protocols::LinkFindIpError) {
		self.first.handle_link_error(error);
		self.second.handle_link_error(error);
	}
	fn handle_ip_error(&mut self, error: protocols::IpError, payload: &[u8]) {
		self.first.handle_ip_error(error, payload);
		self.second.handle_ip_error(error, payload);
	}
	fn handle_ip_fragmented_error(&mut self, ip_info: &protocols::IpInfo) {
		self.first.handle_ip_fragmented_error(ip_info);
		self.second.handle_ip_fragmented_error(ip_info);
	}
	fn handle_ip_not_udp_error(&mut self, ip_info: &protocols::IpInfo, payload: &[u8]) {
		self.first.handle_ip_not_udp_error(ip_info, payload);
		self.second.handle_ip_not_udp_error(ip_info, payload);
	}
	fn handle_udp_error(&mut self, ip_info: &protocols::IpInfo, error: protocols::UdpError, payload: &[u8]) {
		self.first.handle_udp_error(ip_info, error, payload);
		self.second.handle_udp_error(ip_info, error, payload);
	}
	fn handle_dns_too_short(&mut self, ip_info: &protocols::IpInfo, udp_info: &protocols::UdpInfo, payload: &[u8]) {
		self.first.handle_dns_too_short(ip_info, udp_info, payload);
		self.second.handle_dns_too_short(ip_info, udp_info, payload);
	}
	fn handle_dns_is_query(&mut self, ip_info: &protocols::IpInfo, udp_info: &protocols::UdpInfo, dns_info: &protocols::DnsInfo) {
		self.first.handle_dns_is_query(ip_info, udp_info, dns_info);
		self.second.handle_dns_is_query(ip_info, udp_info, dns_info);
	}
	fn handle_dns_is_not_authoritative(&mut self, ip_info: &protocols::IpInfo, udp_info: &protocols::UdpInfo, dns_info: &protocols::DnsInfo) {
		self.first.handle_dns_is_not_authoritative(ip_info, udp_info, dns_info);
		self.second.handle_dns_is_not_authoritative(ip_info, udp_info, dns_info);
	}
	fn handle_dns_has_no_answers(&mut self, ip_info: &protocols::IpInfo, udp_info: &protocols::UdpInfo, dns_info: &protocols::DnsInfo) {
		self.first.handle_dns_has_no_answers(ip_info, udp_info, dns_info);
		self.second.handle_dns_has_no_answers(ip_info, udp_info, dns_info);
	}
	fn handle_non_fatal_forward_error(&mut self, ip_info: &protocols::IpInfo, udp_info: &protocols::UdpInfo, dns_info: &protocols::DnsInfo, dns_data: &[u8], error: &E) {
		self.first.handle_non_fatal_forward_error(ip_info, udp_info, dns_info, dns_data, error);
		self.second.handle_non_fatal_forward_error(ip_info, udp_info, dns_info, dns_data, error);
	}
	fn handle_success(&mut self, ip_info: &protocols::IpInfo, udp_info: &protocols::UdpInfo, dns_info: &protocols::DnsInfo, dns_data: &[u8]) {
		self.first.handle_success(ip_info, udp_info, dns_info, dns_data);
		self.second.handle_success(ip_info, udp_info, dns_info, dns_data);
	}
	fn show_stat(&mut self, stat: &pcap::Stat) {
		self.first.show_stat(stat);
		self.second.show_stat(stat);
	}
}
