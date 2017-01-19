# Overview

Each DNS response packet is put into one `DNSXFR01` message.  A single
`DNSXFR01` message consists of the following data:

	byte magic[8];
	byte nameserver[4]; // IPv4 address
	byte dns_data[];

The `magic` field always contains the ASCII string "DNSXFR01".
`nameserver` contains the encoded IPv4 address of the nameserver if the
DNS response was authoritative and via IPv4 and is zero otherwise.
`dns_data` covers the remaining data of the message (i.e. the message
length needs to be known in advance).

All data is encoded as big-endian.

# Truncated DNS responses

Truncated DNS responses are sent too; this means a forwarder might
truncate a DNS response to limit the size of the `dns_data` field (as an
alternative to dropping packets exceeding the limit), but must ensure to
set the TC flag in the DNS response.

# Using UDP for transport

When using UDP as underlying transport, each `DNSXFR01` message is sent
as a single UDP datagram.  The length of the payload of a UDP datagram
is known by the receiver, and can be used to determine the length of the
`dns_data` field in the `DNSXFR01` message.

# Using TCP for transport

When using TCP as underlying transport, each `DNSXFR01` message is
prefixed by the length of the message (not including its own length) as
16-bit unsigned integer, and then sent using the TCP transport.  Using
the prefixed message length the receiver can determine the length of the
`dns_data` field in the `DNSXFR01` message.

# Additional notes

The original C implementation at
http://www.enyo.de/fw/software/dnslogger/ used a 512 byte buffer for the
`dns_data` field.  When the DNS data was too long the packet was not
sent at all (it did NOT truncate the data, although the protocol would
allow it).

Originally DNS messages were limited to 512 bytes, so this mechanism
didn't drop any normal response.  But using the `EDNS(0)` extension a
client might signal support for larger responses, and `DNSSEC` responses
are often larger than 512 bytes.
