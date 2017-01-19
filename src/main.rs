#[macro_use]
extern crate clap;

#[macro_use]
extern crate dnslogger_utils as utils;

use utils::{pcap,options,capture};
use utils::capture::EventHandler;

use std::net;
use std::io::{self,Write,Read};

mod man;

/// returned a `net::SocketAddr` with undefined address and port
/// matching the address family of the given `target` address
fn bind_addr_for(target: &net::IpAddr) -> net::SocketAddr {
	net::SocketAddr::new(
		match *target {
			net::IpAddr::V4(_) => net::IpAddr::V4(net::Ipv4Addr::new(0, 0, 0, 0)),
			net::IpAddr::V6(_) => net::IpAddr::V6(net::Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0)),
		},
		0,
	)
}

/// `run_inner` connects the forwarder, configures the packet capturing
/// and loops forever to forward captures DNS packets
///
/// `run_inner` only returns on errors (`Result` is used for the `try!`
/// macro)
fn run_inner<'a, F, FC, E>(
	opts: &options::Options,
	forward_connect: &FC,
	error_handler: &mut E)
	-> Result<(), capture::Error<F::Error>>
where
	F: capture::Forwarder,
	FC: Fn() -> Result<F, capture::Error<F::Error>>,
	E: capture::EventHandler<F::Error>
{
	let mut forwarder = try!(forward_connect());

	writeln!(std::io::stderr(), "starting capture").unwrap();
	try!(capture::capture(&opts, &mut forwarder, error_handler));

	// should never be reached
	panic!("capture should never exit without error");
}

/// `run` runs the forwarding forever, restarting it after errors. it
/// ensures it isn't restarted too fast.
///
/// `run` only returns on errors (`Result` is used for the `try!` macro)
fn run<'a, F, FC, E>(
	opts: &options::Options,
	forward_connect: FC,
	error_handler: &mut E) -> !
where
	F: capture::Forwarder,
	FC: Fn() -> Result<F, capture::Error<F::Error>>,
	E: capture::EventHandler<F::Error>
{
	use std::time::{Duration, Instant};
	use std::thread::sleep;

	let restart_distance = Duration::from_secs(5);

	loop {
		let started_at = Instant::now();

		match run_inner(&opts, &forward_connect, error_handler) {
			Err(e) => {
				writeln!(std::io::stderr(), "stopped due to: {}", e).unwrap();
			},
			Ok(_) => {
				panic!("loop should never without error");
			},
		}

		let run_time = started_at.elapsed();
		if run_time < restart_distance {
			let pause = restart_distance - run_time;
			let secs = pause.as_secs() as f64 + (pause.subsec_nanos() as f64 / 1.0e9);
			writeln!(std::io::stderr(), "waiting {} seconds before restarting", secs).unwrap();

			sleep(pause);
		}
	}
}

fn main() {
	let default_device = pcap::Device::lookup().unwrap().name;

	let app = clap_app!(
		@app (clap::App::new("dnslogger-forward"))
		(version: crate_version!())
		(author: crate_authors!())
		(about: "dnslogger-forward forwards a subset of DNS traffic to a central monitoring station for analysis.")
		(@arg interface: -i [INTERFACE] +takes_value default_value(&default_device) "interface to capture packets on")
		(@arg filter: -f [EXPRESSION] default_value("udp and port 53") "filter expression (BPF syntax)")
		(@arg forward_auth_only: -A "forward authoritative answers only")
		(@arg no_forward_empty: -D "do not forward empty answers")
		(@arg tcp_forward: -t "forward data over TCP (default is UDP)")
		(@arg log_interval: -L [SECS] default_value("3600") "write a checkpoint log entry every SECS seconds")
		(@arg testing: -T conflicts_with_all(&["host", "port"]) "enable testing mode (reads from standard input)")
		(@arg verbosity: -v ... "verbose output, include debugging messages")
		(@arg host: +required [HOST] "address to forward DNS packets to")
		(@arg port: +required [PORT] "port to forward DNS packets to")
		(@arg man: --man +hidden conflicts_with_all(&["host", "port"]) "show man page")
	);

	let matches = app.clone().get_matches();
	if matches.is_present("man") {
		man::generate_man(&app);
		return;
	}

	let target = if matches.is_present("testing") {
		utils::test::empty_addr()
	} else {
		net::SocketAddr::new(value_t_or_exit!(matches, "host", net::IpAddr), value_t_or_exit!(matches, "port", u16))
	};

	let opts = options::Options{
		interface: matches.value_of("interface").unwrap(),
		filter: matches.value_of("filter").unwrap(),
		forward_auth_only: matches.is_present("forward_auth_only"),
		no_forward_empty: matches.is_present("no_forward_empty"),
		tcp_forward: matches.is_present("tcp_forward"),
		log_interval: value_t_or_exit!(matches, "log_interval", u32),
		verbose: matches.occurrences_of("verbosity"),
		target: target,
		max_message_size: 4096, // TODO: define command line option
	};

	if matches.is_present("testing") {
		let opts = options::Options{
			max_message_size: 512,
			.. opts
		};
		let mut input : Vec<u8> = Vec::new();
		io::stdin().read_to_end(&mut input).unwrap();
		utils::test::run_test(&opts, &input, &mut io::stdout());
		return;
	}

	println!("Passed options: {:?}", opts);

	let mut event_handler =
		capture::LoggingEventHandler::new(std::io::stderr(), opts.verbose).combine(
			capture::StatisticsEventHandler::new());

	if opts.tcp_forward {
		let tcp_connector = || {
			let tcp_client = try!(net::TcpStream::connect(&opts.target)
				.map_err(|e| { capture::Error::ForwardConnectingError(Box::new(e)) }));
			Ok(utils::dnsxfr01::TcpForwarder::new(tcp_client, opts.max_message_size))
		};

		run(&opts, tcp_connector, &mut event_handler);
	} else {
		let udp_connector = || {
			let udp_client = try!(net::UdpSocket::bind(bind_addr_for(&opts.target.ip()))
				.map_err(|e| { capture::Error::ForwardConnectingError(Box::new(e)) }));
			Ok(utils::dnsxfr01::UdpForwarder::new(udp_client, opts.target.clone(), opts.max_message_size))
		};

		run(&opts, udp_connector, &mut event_handler);
	}
}
