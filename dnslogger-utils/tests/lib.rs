use std::path::PathBuf;

extern crate dnslogger_utils as utils;
use utils::options::Options;
use utils::test::{read_file,empty_addr};

fn default_options() -> Options<'static> {
	Options{
		interface: "",
		filter: "udp and port 53",
		forward_auth_only: false,
		no_forward_empty: false,
		tcp_forward: false,
		log_interval: 3600,
		verbose: 2,
		target: empty_addr(),
		max_message_size: 512,
	}
}

fn run_test<'a>(options: &Options<'a>, input_file: PathBuf) -> bool {
	let mut expected_filename = input_file.clone();
	expected_filename.set_extension("expected");

	let input = read_file(&input_file).unwrap();
	let expected = String::from_utf8(read_file(&expected_filename).unwrap()).unwrap();
	let mut output : Vec<u8> = Vec::new();

	utils::test::run_test(options, &input, &mut output);

	let output = String::from_utf8(output).unwrap();

	if expected != output {
		print!("Test {:?}:\nExpected:\n{}Got:\n{}-----\n", input_file, expected, output);
		return false;
	}

	return true;
}

fn run_directory_tests<F: Fn(PathBuf) -> bool>(directory: PathBuf, callback: F) {
	let mut tests = 0;
	let mut failed = 0;

	for entry in directory.read_dir().unwrap() {
		let entry = entry.unwrap();
		match entry.path().extension() {
			None => continue,
			Some(ext) if ext != "in" => continue,
			_ => (),
		}
		tests += 1;

		if !callback(entry.path()) { failed += 1; }
	}

	println!("Failed {} tests from {}", failed, tests);

	assert!(0 == failed);
}

#[test]
fn test_default() {
	let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
	d.push("resources/testsuite/default");

	// ./dnslogger-forward$(exeext) -v -T
	let options = default_options();

	run_directory_tests(d, move |input_file| {
		run_test(&options, input_file)
	});
}

#[test]
fn test_forward_auth_only() {
	let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
	d.push("resources/testsuite/forward_auth_only");

	// ./dnslogger-forward$(exeext) -A -v -T
	let options = Options{
		forward_auth_only: true,
		.. default_options()
	};

	run_directory_tests(d, move |input_file| {
		run_test(&options, input_file)
	});
}


#[test]
fn test_no_forward_empty() {
	let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
	d.push("resources/testsuite/no_forward_empty");

	// ./dnslogger-forward$(exeext) -D -v -T
	let options = Options{
		no_forward_empty: true,
		.. default_options()
	};

	run_directory_tests(d, move |input_file| {
		run_test(&options, input_file)
	});
}


#[test]
fn test_tcp_forward() {
	let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
	d.push("resources/testsuite/tcp_forward");

	// ./dnslogger-forward$(exeext) -t -v -T
	let options = Options{
		tcp_forward: true,
		.. default_options()
	};

	run_directory_tests(d, move |input_file| {
		run_test(&options, input_file)
	});
}
