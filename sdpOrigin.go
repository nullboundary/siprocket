package siprocket

/*
RFC4566 - https://datatracker.ietf.org/doc/html/rfc4566#section-5.2

5.2.  Origin ("o=")

  o=<username> <sess-id> <sess-version> <nettype> <addrtype> <unicast-address>

  o=- 4000 4001 IN IP4 88.215.55.98

*/

type SdpOrigin struct {
	Username    []byte // Username
	SessId      []byte // Session Id
	SessVer     []byte // Session Version
	NetType     []byte // Network Type
	AddrType    []byte // Address Type
	UnicastAddr []byte // Unicast Address
	Src         []byte // Full source if needed
}

func NewSdpOrigin(username, sessId, sessVer, netType, addrType, unicastAddr, src string) SdpOrigin {
	return SdpOrigin{
		Username:    []byte(username),
		SessId:      []byte(sessId),
		SessVer:     []byte(sessVer),
		NetType:     []byte(netType),
		AddrType:    []byte(addrType),
		UnicastAddr: []byte(unicastAddr),
		Src:         []byte(src),
	}
}

func parseSdpOrigin(v []byte, out *SdpOrigin) {

	pos := 0
	state := FIELD_USERNAME

	// Init the output area
	out.Username = nil
	out.SessId = nil
	out.SessVer = nil
	out.NetType = nil
	out.AddrType = nil
	out.UnicastAddr = nil

	// Keep the source line if needed
	if keep_src {
		out.Src = v
	}

	// Loop through the bytes making up the line
	for pos < len(v) {
		// FSM
		switch state {
		case FIELD_USERNAME:
			if v[pos] == ' ' {
				state = FIELD_SESSID
				pos++
				continue
			}
			out.Username = append(out.Username, v[pos])
		case FIELD_SESSID:
			if v[pos] == ' ' {
				state = FIELD_SESSVER
				pos++
				continue
			}
			out.SessId = append(out.SessId, v[pos])
		case FIELD_SESSVER:
			if v[pos] == ' ' {
				state = FIELD_NETTYPE
				pos++
				continue
			}
			out.SessVer = append(out.SessVer, v[pos])
		case FIELD_NETTYPE:
			if v[pos] == ' ' {
				state = FIELD_ADDRTYPE
				pos++
				continue
			}
			out.NetType = append(out.NetType, v[pos])
		case FIELD_ADDRTYPE:
			if v[pos] == ' ' {
				state = FIELD_UNICASTADDR
				pos++
				continue
			}
			out.AddrType = append(out.AddrType, v[pos])
		case FIELD_UNICASTADDR:
			out.UnicastAddr = append(out.UnicastAddr, v[pos])
		}
		pos++
	}

}
