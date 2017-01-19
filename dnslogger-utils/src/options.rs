use std::net::SocketAddr;

#[derive(Debug)]
pub struct Options<'a> {
	pub interface: &'a str,
	pub filter: &'a str,
	pub forward_auth_only: bool,
	pub no_forward_empty: bool,
	pub tcp_forward: bool,
	pub log_interval: u32,
	pub verbose: u64,
	pub target: SocketAddr,
	pub max_message_size: usize,
}
