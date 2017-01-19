use super::super::protocols;
use std;
use pcap;

pub trait ForwardError: std::error::Error {
	fn fatal(&self) -> bool; // need to reconnect
}

pub trait Forwarder {
	type Error: ForwardError;
	fn forward(&mut self, ip_info: &protocols::IpInfo, udp_info: &protocols::UdpInfo, dns_info: &protocols::DnsInfo, dns_data: &[u8]) -> Result<(), Self::Error>;
}

pub trait EventHandler<E: ForwardError>: Sized {
	fn handle_link_error(&mut self, error: protocols::LinkFindIpError);
	fn handle_ip_error(&mut self, error: protocols::IpError, payload: &[u8]);
	fn handle_ip_fragmented_error(&mut self, ip_info: &protocols::IpInfo);
	fn handle_ip_not_udp_error(&mut self, ip_info: &protocols::IpInfo, payload: &[u8]);
	fn handle_udp_error(&mut self, ip_info: &protocols::IpInfo, error: protocols::UdpError, payload: &[u8]);
	fn handle_dns_too_short(&mut self, ip_info: &protocols::IpInfo, udp_info: &protocols::UdpInfo, payload: &[u8]);
	fn handle_dns_is_query(&mut self, ip_info: &protocols::IpInfo, udp_info: &protocols::UdpInfo, dns_info: &protocols::DnsInfo);
	fn handle_dns_is_not_authoritative(&mut self, ip_info: &protocols::IpInfo, udp_info: &protocols::UdpInfo, dns_info: &protocols::DnsInfo);
	fn handle_dns_has_no_answers(&mut self, ip_info: &protocols::IpInfo, udp_info: &protocols::UdpInfo, dns_info: &protocols::DnsInfo);
	fn handle_non_fatal_forward_error(&mut self, ip_info: &protocols::IpInfo, udp_info: &protocols::UdpInfo, dns_info: &protocols::DnsInfo, dns_data: &[u8], error: &E);
	fn handle_success(&mut self, ip_info: &protocols::IpInfo, udp_info: &protocols::UdpInfo, dns_info: &protocols::DnsInfo, dns_data: &[u8]);
	fn show_stat(&mut self, stat: &pcap::Stat);

	fn combine<O: EventHandler<E>>(self, other: O) -> super::CombinedEventHandler<E, Self, O> {
		super::CombinedEventHandler{
			first: self,
			second: other,
			_marker: std::marker::PhantomData{},
		}
	}
}
