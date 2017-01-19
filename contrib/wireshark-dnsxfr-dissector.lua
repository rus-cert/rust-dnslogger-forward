-- copy or symlink this into your wireshark plugins directory, e.g.
-- ~/.config/wireshark/plugins/

-- the dissector registers heuristics (no fixed ports assigned), and
-- should work out of the box

local function register_dnsxfr()
	local udp_table = DissectorTable.get("udp.port")
	local udp_dns_dissector = udp_table:get_dissector(53)

	local udp_proto = Proto("dnsxfr","DNS-logger forward message")
	local f_magic = ProtoField.new("Magic protocol identifier", "dnsxfr.magic", ftypes.STRING)
	local f_nameserver = ProtoField.new("Nameserver", "dnsxfr.nameserver", ftypes.IPv4)
	udp_proto.fields = { f_magic, f_nameserver }

	local magic0 = "DNSXFR00"
	local magic1 = "DNSXFR01"

	function dissect_message(buffer, pinfo, tree, dns_dissect_cb)
		tree = tree:add(udp_proto, buffer())

		if buffer:len() < 8 then
			tree:append_text(" (packet too short)")
			return
		end

		local magic_tvb = buffer(0, 8)
		local magic = magic_tvb:string()
		local range = buffer(8)
		local magictree = tree:add(f_magic, magic_tvb)

		local version
		if magic == magic0 then
			version = 0
		elseif magic == magic1 then
			version = 1
		else
			magictree:append_text(" (unknown magic string)")
		end
		pinfo.cols.protocol = magic

		-- DNSXFR00 doesn't have the nameserver field
		if 1 == version then
			if range:len() < 4 then
				tree:append_text(" (packet too short)")
				return
			end
			local addr = range(0, 4)
			range = range(4)
			local nstree = tree:add(f_nameserver, addr)
			if 0 == addr:uint() then
				-- 0.0.0.0 is used if the answer is not authoritative or
				-- the client didn't want to send it for other reasons.
				nstree:append_text(" (hidden)")
			end
		end

		dns_dissect_cb(range:tvb(), pinfo, tree)
		-- DNS probably overwrote ours, but we always contain DNS, so
		-- this is not a useful information
		pinfo.cols.protocol = magic
	end

	function udp_proto.dissector(buffer, pinfo, tree)
		dissect_message(buffer, pinfo, tree, function(buffer, pinfo, tree)
			udp_dns_dissector:call(buffer, pinfo, tree)
		end)
	end

	local function udp_heuristic(buffer, pinfo, tree)
		if buffer:len() < 8 then
			return false
		end
		local magic = buffer(0, 8):string()
		if (magic == magic0 or magic == magic1) then
			udp_proto.dissector(buffer, pinfo, tree)
			return true
		end
	end

	udp_proto:register_heuristic("udp", udp_heuristic)


	local tcp_table = DissectorTable.get("tcp.port")
	local tcp_dns_dissector = tcp_table:get_dissector(53)

	local tcp_proto = Proto("dnsxfr-tcp","DNS-logger forward stream")
	local f_msgsize = ProtoField.new("Message length", "dnsxfr.len", ftypes.UINT16) -- tcp mode
	tcp_proto.fields = { f_msgsize }

	function tcp_proto_dissect(buffer, pinfo, tree)
		tree = tree:add(tcp_proto, buffer())
		tree:add(f_msgsize, buffer(0, 2))

		dissect_message(buffer(2):tvb(), pinfo, tree, function(buffer, pinfo, tree)
			-- it seems currently the DNS dissector looks at
			-- pinfo->ptype (lua: port_type) to detect TCP, which we
			-- can't write so even the udp_dns_dissector would expect a
			-- 2-byte length prefix

			-- instead use tcp_dns_dissector (in case they fix it one
			-- day) and create a new bytearray with the length prefix

			local len_prefix = ByteArray.new("00 00")
			local msglen = buffer:len()
			len_prefix:set_index(0, (msglen / 256) % 256)
			len_prefix:set_index(1, msglen % 256)
			local tcp_dns_packet = len_prefix .. buffer(0):bytes()
			tcp_dns_dissector:call(tcp_dns_packet:tvb("DNS data"), pinfo, tree)
		end)

		return buffer:len()
	end

	function tcp_proto_get_len(buffer, pinfo, offset)
		return buffer(offset, 2):uint()
	end

	function tcp_proto.dissector(buffer, pinfo, tree)
		local offset = 0
		local remaining = buffer:len()

		while remaining > 0 do
			if remaining < 2 then
				print("incomplete header")
				-- we need more bytes
				pinfo.desegment_offset = offset
				pinfo.desegment_len = DESEGMENT_ONE_MORE_SEGMENT
				if offset > 0 then
					return offset
				else
					return DESEGMENT_ONE_MORE_SEGMENT
				end
			end

			local msg_size = buffer(offset, 2):uint() + 2

			if remaining < msg_size then
				print(string.format("incomplete message: offset=%d,rem=%d,msg_size=%d", offset, remaining, msg_size))
				local missing = msg_size - remaining
				pinfo.desegment_offset = offset
				pinfo.desegment_len = missing
				if offset > 0 then
					return offset
				else
					return -missing
				end
			end

			tcp_proto_dissect(buffer(offset, msg_size):tvb(), pinfo, tree)

			offset = offset + msg_size
			remaining = remaining - msg_size
		end

		return offset
	end

	tcp_proto:register_heuristic("tcp", tcp_proto.dissector)
end

register_dnsxfr()
