# Overview

Each DNS response packet is put into one `DNSXFR00` message.  A single
`DNSXFR00` message consists of the following data:

	byte magic[8];
	byte dns_data[];

The `magic` field always contains the ASCII string "DNSXFR00".
`dns_data` covers the remaining data of the message (i.e. the message
length needs to be known in advance).

All data is encoded as big-endian.

# Using UDP for transport

When using UDP as underlying transport, each `DNSXFR00` message is sent
as a single UDP datagram.  The length of the payload of a UDP datagram
is known by the receiver, and can be used to determine the length of the
`dns_data` field in the `DNSXFR00` message.

# Using TCP for transport

When using TCP as underlying transport, each `DNSXFR00` message is
prefixed by the length of the message (not including its own length) as
16-bit unsigned integer, and then sent using the TCP transport.  Using
the prefixed message length the receiver can determine the length of the
`dns_data` field in the `DNSXFR00` message.
