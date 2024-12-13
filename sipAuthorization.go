package siprocket

import "bytes"

/*
 RFC 3261 - https://www.ietf.org/rfc/rfc3261.txt - 22 Usage of HTTP Authentication

 Authorization field value consists of credentials containing the
   authentication information of the UA for the realm of the resource
   being requested as well as parameters required in support of
   authentication and replay protection.

	Examples

	Authorization: Digest username="bob",
	realm="biloxi.com",
	nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093",
	uri="sip:bob@biloxi.com",
	qop=auth,
	nc=00000001,
	cnonce="0a4f113b",
	response="6629fae49393a05397450978507c4ef1",
	opaque="5ccc069c403ebaf9f0171e9517f40e41"

	Authorization: Digest username="bob",
	realm="127.0.0.1",
	nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093",
	uri="sip:127.0.0.1",
	response="6629fae49393a05397450978507c4ef1",
	algorithm=MD5

*/

type SipAuth struct {
	Digest    []byte // Digest
	Username  []byte // Username
	Realm     []byte // Realm
	Nonce     []byte // Nonce
	Uri       []byte // Uri
	Qop       []byte // Qop
	Nc        []byte // Nc
	Cnonce    []byte // Cnonce
	Response  []byte // Response
	Algorithm []byte // Algorithm
	Opaque    []byte // Opaque
	Src       []byte // Full source if needed
}

func parseSipAuthorization(v []byte, out *SipAuth) {

	pos := 0
	state := FIELD_DIGEST

	// Init the output area
	out.Username = nil
	out.Realm = nil
	out.Nonce = nil
	out.Uri = nil
	out.Qop = nil
	out.Nc = nil
	out.Cnonce = nil
	out.Response = nil
	out.Algorithm = nil
	out.Opaque = nil
	out.Src = nil

	// Keep the source line if needed
	if keep_src {
		out.Src = v
	}

	// Loop through the bytes making up the line
	for pos < len(v) {
		switch state {
		case FIELD_DIGEST:
			if bytes.HasPrefix(v[pos:], []byte("username=\"")) {
				state = FIELD_USERNAME
				pos += len("username=\"")
				continue
			}
		case FIELD_USERNAME:
			if bytes.HasPrefix(v[pos:], []byte("\",")) {
				state = FIELD_REALM
				pos += len("\",")
				continue
			}
			out.Username = append(out.Username, v[pos])

		case FIELD_REALM:
			if bytes.HasPrefix(v[pos:], []byte("realm=\"")) {
				state = FIELD_REALM
				pos += len("realm=\"")
				continue
			}
			if bytes.HasPrefix(v[pos:], []byte("\",")) {
				state = FIELD_NONCE
				pos += len("\",")
				continue
			}
			out.Realm = append(out.Realm, v[pos])

		case FIELD_NONCE:
			if bytes.HasPrefix(v[pos:], []byte("nonce=\"")) {
				state = FIELD_NONCE
				pos += len("nonce=\"")
				continue
			}
			if bytes.HasPrefix(v[pos:], []byte("\",")) {
				state = FIELD_URI
				pos += len("\",")
				continue
			}
			out.Nonce = append(out.Nonce, v[pos])

		case FIELD_URI:
			if bytes.HasPrefix(v[pos:], []byte("uri=\"")) {
				state = FIELD_URI
				pos += len("uri=\"")
				continue
			}
			if bytes.HasPrefix(v[pos:], []byte("\",")) {
				state = FIELD_RESPONSE
				pos += len("\",")
				continue
			}
			out.Uri = append(out.Uri, v[pos])

		case FIELD_RESPONSE:
			if bytes.HasPrefix(v[pos:], []byte("response=\"")) {
				state = FIELD_RESPONSE
				pos += len("response=\"")
				continue
			}
			if bytes.HasPrefix(v[pos:], []byte("\",")) {
				state = FIELD_ALGORITHM
				pos += len("\",")
				continue
			}
			out.Response = append(out.Response, v[pos])

		case FIELD_ALGORITHM:
			if bytes.HasPrefix(v[pos:], []byte("algorithm=")) {
				state = FIELD_ALGORITHM
				pos += len("algorithm=")
				continue
			}
			if bytes.HasPrefix(v[pos:], []byte(",")) {
				state = FIELD_OPAQUE
				pos += len(",")
				continue
			}
			out.Algorithm = append(out.Algorithm, v[pos])

		case FIELD_OPAQUE:
			if bytes.HasPrefix(v[pos:], []byte("opaque=\"")) {
				state = FIELD_OPAQUE
				pos += len("opaque=\"")
				continue
			}
			if bytes.HasPrefix(v[pos:], []byte("\",")) {
				state = FIELD_QOP
				pos += len("\",")
				continue
			}
			out.Opaque = append(out.Opaque, v[pos])

		case FIELD_QOP:
			if bytes.HasPrefix(v[pos:], []byte("qop=")) {
				state = FIELD_QOP
				pos += len("qop=")
				continue
			}
			if bytes.HasPrefix(v[pos:], []byte(",")) {
				state = FIELD_NC
				pos += len(",")
				continue
			}
			out.Qop = append(out.Qop, v[pos])

		case FIELD_NC:
			if bytes.HasPrefix(v[pos:], []byte("nc=")) {
				state = FIELD_NC
				pos += len("nc=")
				continue
			}
			if bytes.HasPrefix(v[pos:], []byte(",")) {
				state = FIELD_CNONCE
				pos += len(",")
				continue
			}
			out.Nc = append(out.Nc, v[pos])

		case FIELD_CNONCE:
			if bytes.HasPrefix(v[pos:], []byte("cnonce=\"")) {
				state = FIELD_CNONCE
				pos += len("cnonce=\"")
				continue
			}
			if bytes.HasPrefix(v[pos:], []byte("\",")) {
				state = FIELD_DIGEST
				pos += len("\",")
				continue
			}
			out.Cnonce = append(out.Cnonce, v[pos])
		}
		pos++
	}
}
