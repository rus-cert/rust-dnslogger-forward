use std::path::PathBuf;
use std::net::SocketAddr;
use std::io::{self,Read,Write};
use std::fs::File;

use options::Options;
use capture;
use protocols;

mod logging;
mod forwarder;
use self::forwarder::{Receiver,TcpReceiver,UdpReceiver,DnsXfr01Protocol};

pub fn empty_addr() -> SocketAddr {
	use std::net::{IpAddr,Ipv4Addr};

	SocketAddr::new(
		IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
		0,
	)
}

pub fn read_file(filename: &PathBuf) -> io::Result<Vec<u8>> {
	let mut data: Vec<u8> = Vec::new();
	try!(try!(File::open(filename)).read_to_end(&mut data));
	Ok(data)
}

fn run_test_inner<'a, P: DnsXfr01Protocol, W: Write>(options: &Options<'a>, input: &[u8], writer: &mut W) {
	let (mut receiver, mut forwarder) = P::new().unwrap();

	let mut event_handler =
		logging::TestLoggingEventHandler::new(writer, options.tcp_forward);

	capture::test_packet(options, &mut forwarder, &mut event_handler, protocols::Linktype::DLT_IPV4, &input).unwrap();

	receiver.receive(&mut event_handler);
}

pub fn run_test<'a, W: Write>(options: &Options<'a>, input: &[u8], writer: &mut W) {
	if options.tcp_forward {
		run_test_inner::<TcpReceiver, _>(options, input, writer);
	} else {
		run_test_inner::<UdpReceiver, _>(options, input, writer);
	}
}
