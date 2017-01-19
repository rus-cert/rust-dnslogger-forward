# Introduction

`rust-dnslogger-forward` is a [rust](https://www.rust-lang.org/) clone
of [dnslogger-forward](http://www.enyo.de/fw/software/dnslogger/).

The command line interface should be compatible, but the output will
differ.

`rust-dnslogger-forward`:
* captures UDP packets with source or destination port 53 (DNS)
* forwards DNS responses to another server using the
  [DNSXFR01 protocol](protocols/dnsxfr01.md); the sent data also
  includes the nameserver for authoritative responses on IPv4.
* supports IPv4 and IPv6, but not fragmented IP packets


# Purpose

In certain cases it is useful to know which address a name pointed to at
a given point in time (e.g. to analyse a botnet).  DNS doesn't provide
the history itself, so you need to log and store DNS responses.

It also helps to find potential aliases for an IP address, as a PTR
request usually only returns a single hostname, even if many (valid)
names point to the address.  Not all those names necessarily belong the
owner of the address; anyone can make their own names point to any
address.

By analysing SRV and similar records one can guess which services
were provided by a host.

Also see http://www.enyo.de/fw/software/dnslogger/.


# Privacy

DNS responses and queries are sent unencrypted over the network; DNSSEC
(if used and supported) only provides integrity and authenticity.  This
means that many entities already can read the data.

Collecting, storing and publishing the data still has various impacts on
the privacy of your users:

- If a user uses special domains (e.g. a private mail server) you can
  track their online presence over time.
- While scanning all "active" IPv4 addresses is rather trivial, IPv6
  addresses are hard to guess.  A user might try to hide their IPv6-only
  server and use a hard-to-guess name; by publishing that name the
  IPv6-address is easy to find, and might expose the IPv6-only server to
  attackers.


# Usage

Compile and run it with cargo; to list all options run:

	cargo run --release -- -h

When calling through `cargo run` the `dnslogger-forward` options should
be put after the `--` marker.
