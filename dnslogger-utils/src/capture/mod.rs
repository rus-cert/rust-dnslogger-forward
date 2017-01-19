use pcap;
// use libc;

use super::options::Options;
use super::protocols::{self,Linktype};

mod traits;
pub use self::traits::*;

mod logging_event_handler;
pub use self::logging_event_handler::*;

mod combined_event_handlers;
pub use self::combined_event_handlers::*;

mod statistics_event_handler;
pub use self::statistics_event_handler::*;

use std::{error,fmt};
use std::time::{Duration, Instant};

#[derive(Debug)]
pub enum Error<FE: ForwardError> {
	ForwardConnectingError(Box<error::Error>),
	OpenError(pcap::Error),
	FilterError(pcap::Error),
	CaptureError(pcap::Error),
	UnknownLinkType(Result<String, pcap::Error>),
	StatError(pcap::Error),
	HandledError,
	FatalForwardError(FE),
}
impl<FE: ForwardError> fmt::Display for Error<FE> {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		use self::Error::*;
		match *self {
			ForwardConnectingError(ref e) => write!(f, "couldn't connect forwarder: {}", e),
			OpenError(ref e) => write!(f, "couldn't open capture device: {}", e),
			FilterError(ref e) => write!(f, "couldn't apply capture filter: {}", e),
			CaptureError(ref e) => write!(f, "failed capturing packet: {}", e),
			UnknownLinkType(Ok(ref link_type_name)) => write!(f, "unknown link type of capture handle: {}", link_type_name),
			UnknownLinkType(Err(ref e)) => write!(f, "unknown link type of capture handle, failed to get readable name: {}", e),
			StatError(ref e) => write!(f, "failed to get capture stats: {}", e),
			HandledError => write!(f, "handling captured packet failed, but was handled"),
			FatalForwardError(ref e) => write!(f, "fatal failure forwading a packet: {}", e),
		}
	}
}

impl<FE: ForwardError> error::Error for Error<FE> {
	fn description(&self) -> &str {
		use self::Error::*;
		match *self {
			ForwardConnectingError(_) => "couldn't connect forwarder",
			OpenError(_) => "couldn't open capture device",
			FilterError(_) => "couldn't apply capture filter",
			CaptureError(_) => "failed capturing packet",
			UnknownLinkType(Ok(_)) => "unknown link type of capture handle",
			UnknownLinkType(Err(_)) => "unknown link type of capture handle, failed to get readable name",
			StatError(_) => "failed to get capture stats",
			HandledError => "handling captured packet failed, but was handled",
			FatalForwardError(_) => "fatal failure forwading a packet",
		}
	}
	fn cause(&self) -> Option<&error::Error> {
		use self::Error::*;
		match *self {
			ForwardConnectingError(ref e) => Some(e.as_ref()),
			OpenError(ref e) => Some(e),
			FilterError(ref e) => Some(e),
			CaptureError(ref e) => Some(e),
			StatError(ref e) => Some(e),
			UnknownLinkType(_) => None,
			HandledError => None,
			FatalForwardError(ref e) => Some(e),
		}
	}
}

fn get_link_type<FE: ForwardError>(lt: pcap::Linktype) -> Result<protocols::Linktype, Error<FE>> {
	match protocols::Linktype::try_from(&lt) {
		Some(res) => Ok(res),
		None => Err(Error::UnknownLinkType(lt.get_name())),
	}
}

struct Context<'a, 'o: 'a, F: 'a + Forwarder, E: 'a + EventHandler<F::Error>> {
	options: &'a Options<'o>,
	forwarder: &'a mut F,
	e: &'a mut E,
	datalink: &'a protocols::Linktype,
}

fn handle_packet<'a, F: Forwarder, E: EventHandler<F::Error>>(ctx: &mut Context<F, E>, packet: &[u8]) -> Result<(), Error<F::Error>> {
	use self::Error::HandledError;
	let (family, ip_data) = try!(ctx.datalink.find_ip_layer(packet).map_err(|e| { ctx.e.handle_link_error(e); HandledError }));

	let (ip_info, udp_data) = try!(family.check_packet(ip_data).map_err(|e| { ctx.e.handle_ip_error(e, ip_data); HandledError }));
	if None != ip_info.fragment {
		ctx.e.handle_ip_fragmented_error(&ip_info);
		return Err(HandledError);
	}
	if 17 != ip_info.protocol {
		ctx.e.handle_ip_not_udp_error(&ip_info, udp_data);
		return Err(HandledError);
	}

	let (udp_info, dns_data) = try!(protocols::check_udp(family, &ip_info, ip_data, udp_data).map_err(|e| { ctx.e.handle_udp_error(&ip_info, e, udp_data); HandledError }));
	let dns_info = match protocols::dns::dns_info(dns_data) {
		Some(res) => res,
		None => {
			ctx.e.handle_dns_too_short(&ip_info, &udp_info, dns_data);
			return Err(HandledError);
		}
	};

	if dns_info.qr == protocols::DnsType::Query {
		ctx.e.handle_dns_is_query(&ip_info, &udp_info, &dns_info);
		return Err(HandledError);
	}
	if ctx.options.forward_auth_only && !dns_info.authoritative_answer {
		ctx.e.handle_dns_is_not_authoritative(&ip_info, &udp_info, &dns_info);
		return Err(HandledError);
	}
	if ctx.options.no_forward_empty && 0 == dns_info.ancount {
		ctx.e.handle_dns_has_no_answers(&ip_info, &udp_info, &dns_info);
		return Err(HandledError);
	}
	match ctx.forwarder.forward(&ip_info, &udp_info, &dns_info, &dns_data) {
		Ok(_) => (),
		Err(e) => {
			if e.fatal() {
				return Err(Error::FatalForwardError(e));
			} else {
				ctx.e.handle_non_fatal_forward_error(&ip_info, &udp_info, &dns_info, &dns_data, &e);
				return Err(HandledError);
			}
		}
	}
	ctx.e.handle_success(&ip_info, &udp_info, &dns_info, &dns_data);
	Ok(())
}

/*
// returns at least "1" (0 would signal blocking)
fn timeout_duration(elapsed: &Duration, wait: &Duration) -> i32 {
	use std::cmp::{max,min};
	use std::i32::MAX;

	if elapsed >= wait { return 1i32; }
	let remaining = *wait - *elapsed;

	let v = match remaining.as_secs().overflowing_mul(1000) {
		(_, true) => return MAX,
		(v, false) => match v.overflowing_add((remaining.subsec_nanos() / 1000000) as u64) {
			(_, true) => return MAX,
			(v, false) => v,
		}
	};
	max(1, min(v, MAX as u64) as i32)
}
*/

pub fn capture<'a, F: Forwarder, E: EventHandler<F::Error>>(options: &Options<'a>, forwarder: &mut F, event_handler: &mut E) -> Result<(), Error<F::Error>> {
	// delay captured packets at most 1000 ms ("timeout") until they get
	// delivered to userspace
	let inactive_cap = try_wrap_err!(Error::OpenError, pcap::Capture::from_device(options.interface)).timeout(1000);
	let mut cap = try_wrap_err!(Error::OpenError, inactive_cap.open());
	try_wrap_err!(Error::FilterError, cap.filter(options.filter));
	let datalink = try!(get_link_type(cap.get_datalink()));
	let mut ctx = Context{
		options: options,
		forwarder: forwarder,
		e: event_handler,
		datalink: &datalink,
	};

	let stat_wait = Duration::from_secs(options.log_interval as u64);

	let mut last_stat_at = Instant::now();

/*	let raw_fd = {
		use std::os::unix::io::AsRawFd;
		cap.as_raw_fd()
	};
	let mut poll_fd = libc::pollfd{
		fd: raw_fd,
		events: 0,
		revents: 0,
	};
*/
	loop {
/*		let timeout = timeout_duration(&last_stat_at.elapsed(), &stat_wait);

		poll_fd.events = libc::POLLIN;
		let active_fds = unsafe {
			libc::poll(&mut poll_fd, 1, timeout as i32)
		};
		if 0 != active_fds
*/
		{
			let packet = try_wrap_err!(Error::CaptureError, cap.next());
			match handle_packet(&mut ctx, packet.data) {
				Ok(_) => (),
				Err(Error::HandledError) => (),
				Err(e) => return Err(e),
			}
		}

		if last_stat_at.elapsed() >= stat_wait {
			last_stat_at = Instant::now();
			ctx.e.show_stat(&try_wrap_err!(Error::StatError, cap.stats()));
		}
	}
}

pub fn test_packet<'a, F: Forwarder, E: EventHandler<F::Error>>(options: &Options<'a>, forwarder: &mut F, event_handler: &mut E, datalink: Linktype, packet: &[u8]) -> Result<(), Error<F::Error>> {
	let mut ctx = Context{
		options: options,
		forwarder: forwarder,
		e: event_handler,
		datalink: &datalink,
	};

	match handle_packet(&mut ctx, packet) {
		Ok(_) => (),
		Err(Error::HandledError) => (),
		Err(e) => return Err(e),
	}

	Ok(())
}
