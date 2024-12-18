package siprocket

import (
	"fmt"
	"strings"
)

/*
 RFC 3261 - https://www.ietf.org/rfc/rfc3261.txt - 8.1.1.7 Via

 The Via header field indicates the transport used for the transaction
and identifies the location where the response is to be sent.  A Via
header field value is added only after the transport that will be
used to reach the next hop has been selected (which may involve the
usage of the procedures in [4]).

*/

type SipVia struct {
	Trans  string // Type of Transport udp, tcp, tls, sctp etc
	Host   []byte // Host part
	Port   []byte // Port number
	Branch []byte //
	Rport  []byte //
	Maddr  []byte //
	Ttl    []byte //
	Rcvd   []byte //
	Src    []byte // Full source if needed
}

func NewSipVia(trans, host, port, branch, rport, src string) SipVia {
	return SipVia{
		Trans:  trans,
		Host:   []byte(host),
		Port:   []byte(port),
		Branch: []byte(branch),
		Rport:  []byte(rport),
		Src:    []byte(src),
	}
}

func parseSipVia(v []byte, out *SipVia) {

	pos := 0
	state := FIELD_BASE

	// Init the output area
	out.Trans = ""
	out.Host = nil
	out.Port = nil
	out.Branch = nil
	out.Rport = nil
	out.Maddr = nil
	out.Ttl = nil
	out.Rcvd = nil
	out.Src = nil

	// Keep the source line if needed
	if keep_src {
		out.Src = v
	}

	// Loop through the bytes making up the line
	for pos < len(v) {
		// FSM
		switch state {
		case FIELD_BASE:
			if v[pos] != ' ' {
				// Not a space
				if getString(v, pos, pos+8) == "SIP/2.0/" {
					// Transport type
					state = FIELD_HOST
					pos = pos + 8
					if strings.ToUpper(getString(v, pos, pos+3)) == "UDP" {
						out.Trans = "udp"
						pos = pos + 3
						fmt.Printf("pos-upd:%d", pos)
						continue
					}
					if strings.ToUpper(getString(v, pos, pos+3)) == "TCP" {
						out.Trans = "tcp"
						pos = pos + 3
						continue
					}
					if strings.ToUpper(getString(v, pos, pos+3)) == "TLS" {
						out.Trans = "tls"
						pos = pos + 3
						continue
					}
					if strings.ToUpper(getString(v, pos, pos+4)) == "SCTP" {
						out.Trans = "sctp"
						pos = pos + 4
						continue
					}
					if strings.ToUpper(getString(v, pos, pos+3)) == "WSS" {
						out.Trans = "wss"
						pos = pos + 3
						continue
					}
					if strings.ToUpper(getString(v, pos, pos+2)) == "WS" {
						out.Trans = "ws"
						pos = pos + 2
						continue
					}
				}
				// Look for a Branch identifier
				if getString(v, pos, pos+7) == "branch=" {
					state = FIELD_BRANCH
					pos = pos + 7
					continue
				}
				// Look for a Rport identifier
				if getString(v, pos, pos+6) == "rport=" {
					state = FIELD_RPORT
					pos = pos + 6
					continue
				}
				// Look for a maddr identifier
				if getString(v, pos, pos+6) == "maddr=" {
					state = FIELD_MADDR
					pos = pos + 6
					continue
				}
				// Look for a ttl identifier
				if getString(v, pos, pos+4) == "ttl=" {
					state = FIELD_TTL
					pos = pos + 4
					continue
				}
				// Look for a recevived identifier
				if getString(v, pos, pos+9) == "received=" {
					state = FIELD_REC
					pos = pos + 9
					continue
				}
			}

		case FIELD_HOST:
			if v[pos] == ':' {
				state = FIELD_PORT
				pos++
				continue
			}
			if v[pos] == ';' {
				state = FIELD_BASE
				pos++
				continue
			}
			if v[pos] == ' ' {
				pos++
				continue
			}
			out.Host = append(out.Host, v[pos])

		case FIELD_PORT:
			if v[pos] == ';' {
				state = FIELD_BASE
				pos++
				continue
			}
			out.Port = append(out.Port, v[pos])

		case FIELD_BRANCH:
			if v[pos] == ';' {
				state = FIELD_BASE
				pos++
				continue
			}
			out.Branch = append(out.Branch, v[pos])

		case FIELD_RPORT:
			if v[pos] == ';' {
				state = FIELD_BASE
				pos++
				continue
			}
			out.Rport = append(out.Rport, v[pos])

		case FIELD_MADDR:
			if v[pos] == ';' {
				state = FIELD_BASE
				pos++
				continue
			}
			out.Maddr = append(out.Maddr, v[pos])

		case FIELD_TTL:
			if v[pos] == ';' {
				state = FIELD_BASE
				pos++
				continue
			}
			out.Ttl = append(out.Ttl, v[pos])

		case FIELD_REC:
			if v[pos] == ';' {
				state = FIELD_BASE
				pos++
				continue
			}
			out.Rcvd = append(out.Rcvd, v[pos])
		}
		pos++
	}
}

func MarshalSipVia(via *SipVia) string {
	var sb strings.Builder

	sb.WriteString(HEADER_VIA + ": ")

	// Append transport protocol
	sb.WriteString("SIP/2.0/")
	sb.WriteString(strings.ToUpper(via.Trans))
	sb.WriteString(" ")

	// Append host and port
	sb.Write(via.Host)
	if len(via.Port) > 0 {
		sb.WriteString(":")
		sb.Write(via.Port)
	}

	// Append parameters
	if len(via.Rport) > 0 {
		sb.WriteString(";rport=")
		sb.Write(via.Rport)
	} else {
		sb.WriteString(";rport")
	}
	if len(via.Branch) > 0 {
		sb.WriteString(";branch=")
		sb.Write(via.Branch)
	}
	if len(via.Maddr) > 0 {
		sb.WriteString(";maddr=")
		sb.Write(via.Maddr)
	}
	if len(via.Ttl) > 0 {
		sb.WriteString(";ttl=")
		sb.Write(via.Ttl)
	}
	if len(via.Rcvd) > 0 {
		sb.WriteString(";received=")
		sb.Write(via.Rcvd)
	}

	sb.WriteString(ENDL)

	return sb.String()
}
