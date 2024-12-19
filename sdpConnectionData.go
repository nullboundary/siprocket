package siprocket

/*
RFC4566 - https://tools.ietf.org/html/rfc4566#section-5.7

5.7.  Connection Data ("c=")

  c=<nettype> <addrtype> <connection-address>

  c=IN IP4 88.215.55.98
*/

type SdpConnData struct {
	NetType  []byte // Network Type
	AddrType []byte // Address Type
	ConnAddr []byte // Connection Address
	Src      []byte // Full source if needed
}

func NewSdpConnData(netType, addrType, connAddr, src string) SdpConnData {
	return SdpConnData{
		NetType:  []byte(netType),
		AddrType: []byte(addrType),
		ConnAddr: []byte(connAddr),
		Src:      []byte(src),
	}
}

func parseSdpConnectionData(v []byte, out *SdpConnData) {

	pos := 0
	state := FIELD_NETTYPE

	// Init the output area
	out.NetType = nil
	out.AddrType = nil
	out.ConnAddr = nil
	out.Src = nil

	// Keep the source line if needed
	if keep_src {
		out.Src = v
	}

	// Loop through the bytes making up the line
	for pos < len(v) {
		// FSM
		switch state {
		case FIELD_NETTYPE:
			if v[pos] == ' ' {
				state = FIELD_ADDRTYPE
				pos++
				continue
			}
			out.NetType = append(out.NetType, v[pos])

		case FIELD_ADDRTYPE:
			if v[pos] == ' ' {
				state = FIELD_CONNADDR
				pos++
				continue
			}
			out.AddrType = append(out.AddrType, v[pos])

		case FIELD_CONNADDR:
			if v[pos] == ' ' {
				state = FIELD_BASE
				pos++
				continue
			}
			out.ConnAddr = append(out.ConnAddr, v[pos])
		}
		pos++
	}
}
