use std::net::{UdpSocket,TcpListener,TcpStream,SocketAddr,IpAddr,Ipv4Addr};
use std::io::{self,Read,Write};
use std::time::Duration;
use std::fmt;

use capture;
use dnsxfr01;

fn localhost_any_port_addr() -> SocketAddr {
	SocketAddr::new(
		IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
		0,
	)
}

struct HexSlice<'a>(&'a [u8]);
impl<'a> fmt::LowerHex for HexSlice<'a> {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		for b in self.0 {
			try!(write!(f, "{:02x}", b));
		}
		Ok(())
	}
}

pub trait Receiver {
	fn receive<W: Write>(&mut self, writer: &mut W);
}

pub trait DnsXfr01Protocol {
	type Receiver: Receiver;
	type Forwarder: capture::Forwarder<Error=dnsxfr01::DnsXfr01Error>;

	fn new() -> io::Result<(Self::Receiver, Self::Forwarder)>;
}

pub struct UdpReceiver {
	socket: UdpSocket,
}

impl Receiver for UdpReceiver {
	fn receive<W: Write>(&mut self, writer: &mut W) {
		let mut buf = vec![0u8; 4096];
		self.socket.set_read_timeout(Some(Duration::from_millis(100))).unwrap();
		let (size, _) = match self.socket.recv_from(&mut buf) {
			Err(_) => { writeln!(writer, "dnslogger-forward: debug: No data received.").unwrap(); return; },
			Ok(r) => r,
		};
		writeln!(writer, "dnslogger-forward: Received data: {:x}", HexSlice(&buf[0..size])).unwrap();
	}
}

impl DnsXfr01Protocol for UdpReceiver {
	type Receiver = UdpReceiver;
	type Forwarder = dnsxfr01::UdpForwarder;

	fn new() -> io::Result<(Self::Receiver, Self::Forwarder)> {
		let udp_server = try!(UdpSocket::bind(localhost_any_port_addr()));
		let udp_client = try!(UdpSocket::bind(localhost_any_port_addr()));
		let server_addr = try!(udp_server.local_addr());

		Ok((
			UdpReceiver{
				socket: udp_server,
			},
			dnsxfr01::UdpForwarder::new(udp_client, server_addr, 512),
		))
	}
}

pub struct TcpReceiver {
	socket: TcpStream,
}

impl Receiver for TcpReceiver {
	fn receive<W: Write>(&mut self, writer: &mut W) {
		let mut buf = vec![0u8; 4096];
		self.socket.set_read_timeout(Some(Duration::from_millis(100))).unwrap();

		let mut total_size = 0;

		while total_size < buf.len() {
			let size = match self.socket.read(&mut buf[total_size..]) {
				Err(_) => break,
				Ok(r) => r,
			};
			total_size += size;
		}

		if 0 == total_size {
			writeln!(writer, "dnslogger-forward: debug: No data received.").unwrap();
		} else {
			writeln!(writer, "dnslogger-forward: Received data: {:x}", HexSlice(&buf[0..total_size])).unwrap();
		}
	}
}

impl DnsXfr01Protocol for TcpReceiver {
	type Receiver = TcpReceiver;
	type Forwarder = dnsxfr01::TcpForwarder;

	fn new() -> io::Result<(Self::Receiver, Self::Forwarder)> {
		let tcp_server = try!(TcpListener::bind(localhost_any_port_addr()));
		let tcp_client = try!(TcpStream::connect(try!(tcp_server.local_addr())));
		let (tcp_server_conn, _) = try!(tcp_server.accept());

		Ok((
			TcpReceiver{
				socket: tcp_server_conn,
			},
			dnsxfr01::TcpForwarder::new(tcp_client, 512),
		))
	}
}
