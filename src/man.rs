use clap::{self,ArgSettings};
use std::ascii::AsciiExt;

fn escape<S: ToString+?Sized>(s: &S) -> String {
	s.to_string().replace('\\', "\\\\").replace('-', "\\-")
}

pub fn generate_man<'a, 'b>(app: &clap::App<'a, 'b>) where 'a: 'b {
	println!(".TH {} {}", escape(&app.get_name().to_ascii_uppercase()), 1);
	println!(".SH NAME");
	println!("{}", escape(&app.get_name()));
	println!(".SH SYNOPSIS");
	println!(".B {}", escape(&app.p.create_usage_no_title(&[])));
	match app.p.meta.about {
		Some(about) => {
			println!(".SH DESCRIPTION");
			println!("{}", escape(about));
		},
		None => (),
	}
	if app.p.has_flags() {
		println!(".SH FLAGS");
		for o in app.p.flags() {
			if o.b.settings.is_set(ArgSettings::Hidden) { continue; }
			let mut variants : Vec<String> = vec![];
			if let Some(short) = o.s.short {
				variants.push(format!("-{}", escape(&short)));
			}
			if let Some(long) = o.s.long {
				variants.push(format!("--{}", escape(long)));
			}
			if let Some(ref aliases) = o.s.aliases {
				for &(alias, visible) in aliases {
					if visible {
						variants.push(format!("--{}", escape(alias)));
					}
				}
			}
			let variants : Vec<String> = variants.into_iter().map(|s| { format!("\\fB{}\\fR", s) }).collect();
			println!(".TP\n.BR {}", variants.join(" \", \" "));
			if let Some(desc) = o.b.help {
				println!("{}", escape(desc));
			}
		}
	}
	if app.p.has_opts() || app.p.has_positionals() {
		println!(".SH OPTIONS");
		for o in app.p.opts() {
			if o.b.settings.is_set(ArgSettings::Hidden) { continue; }
			let mut variants : Vec<String> = vec![];
			if let Some(short) = o.s.short {
				variants.push(format!("-{}", escape(&short)));
			}
			if let Some(long) = o.s.long {
				variants.push(format!("--{}", escape(long)));
			}
			if let Some(ref aliases) = o.s.aliases {
				for &(alias, visible) in aliases {
					if visible {
						variants.push(format!("--{}", escape(alias)));
					}
				}
			}
			let name = match o.v.val_names {
				None => format!("\\fI{}\\fR", escape(o.b.name)),
				Some(ref names) => {
					let names : Vec<String> = names.values().map(|s| { format!("\\fI{}\\fR", escape(s)) }).collect();
					names.join(" ")
				}
			};
			let variants : Vec<String> = variants.into_iter().map(|s| { format!("\\fB{}\\fR \" \" {}", s, name) }).collect();
			println!(".TP\n.BR {}", variants.join(" \", \" "));
			if let Some(desc) = o.b.help {
				println!("{}", escape(desc));
			}
		}
		for o in app.p.positionals() {
			if o.b.settings.is_set(ArgSettings::Hidden) { continue; }
			let name = match o.v.val_names {
				None => format!("\\fI{}\\fR", escape(o.b.name)),
				Some(ref names) => {
					let names : Vec<String> = names.values().map(|s| { format!("\\fI{}\\fR", escape(s)) }).collect();
					names.join(" ")
				}
			};
			println!(".TP\n.BR {}", name);
			if let Some(desc) = o.b.help {
				println!("{}", escape(desc));
			}
		}
	}
	match app.p.meta.author {
		Some(ref author) => {
			println!(".SH AUTHOR");
			println!(".B {}", escape(&app.get_name()));
			println!("was written by {}.", escape(author));
		}
		None => (),
	}
	println!("");
}
