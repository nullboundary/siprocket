package siprocket

/*
 RFC 3261 - https://www.ietf.org/rfc/rfc3261.txt - 20.44 WWW-Authenticate

  A WWW-Authenticate header field value contains an authentication
   challenge.  See Section 22.2 for further details on its usage.

   Example:

      WWW-Authenticate: Digest realm="atlanta.com",
        domain="sip:boxesbybob.com", qop="auth",
        nonce="f84f1cec41e6cbe5aea9c8e88d359",
        opaque="", stale=FALSE, algorithm=MD5

*/

type SipWWWAuthenticate struct {
	Realm     []byte // Realm
	Domain    []byte // Domain
	Qop       []byte // Qop
	Nonce     []byte // Nonce
	Opaque    []byte // Opaque
	Stale     []byte // Stale
	Algorithm []byte // Algorithm
	Src       []byte // Full source if needed
}

func parseSipWWWAuthenticate(v []byte, out *SipWWWAuthenticate) {

	pos := 0
	state := FIELD_REALM

	// Init the output area
	out.Realm = nil
	out.Domain = nil
	out.Qop = nil
	out.Nonce = nil
	out.Opaque = nil
	out.Stale = nil
	out.Algorithm = nil
	out.Src = nil

	// Keep the source line if needed
	if keep_src {
		out.Src = v
	}

	// Loop through the bytes making up the line
	for pos < len(v) {
		// FSM
		//fmt.Println("POS:", pos, "CHR:", string(v[pos]), "STATE:", state)
		switch state {
		case FIELD_DIGEST:
			if v[pos] == ' ' {
				state = FIELD_REALM
				pos++
				continue
			}
		case FIELD_REALM:
			if v[pos] == ' ' {
				state = FIELD_DOMAIN
				pos++
				continue
			}
			out.Realm = append(out.Realm, v[pos])

		case FIELD_DOMAIN:
			if v[pos] == ' ' {
				state = FIELD_QOP
				pos++
				continue
			}
			out.Domain = append(out.Domain, v[pos])

		case FIELD_QOP:
			if v[pos] == ' ' {
				state = FIELD_NONCE
				pos++
				continue
			}
			out.Qop = append(out.Qop, v[pos])

		case FIELD_NONCE:
			if v[pos] == ' ' {
				state = FIELD_OPAQUE
				pos++
				continue
			}
			out.Nonce = append(out.Nonce, v[pos])

		case FIELD_OPAQUE:
			if v[pos] == ' ' {
				state = FIELD_STALE
				pos++
				continue
			}
			out.Opaque = append(out.Opaque, v[pos])

		case FIELD_STALE:
			if v[pos] == ' ' {
				state = FIELD_ALGORITHM
				pos++
				continue
			}
			out.Stale = append(out.Stale, v[pos])

		case FIELD_ALGORITHM:
			out.Algorithm = append(out.Algorithm, v[pos])
		}
		pos++
	}
}
