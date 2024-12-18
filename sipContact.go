package siprocket

import (
	"bytes"
	"errors"
)

/*

RFC 3261 - https://www.ietf.org/rfc/rfc3261.txt - 8.1.1.8 Contact

   The Contact header field provides a SIP or SIPS URI that can be used
   to contact that specific instance of the UA for subsequent requests.
   The Contact header field MUST be present and contain exactly one SIP
   or SIPS URI in any request that can result in the establishment of a
   dialog.

Examples:

   Contact: "Mr. Watson" <sip:watson@worcester.bell-telephone.com>
      ;q=0.7; expires=3600,
      "Mr. Watson" <mailto:watson@bell-telephone.com> ;q=0.1
   m: <sips:bob@192.0.2.4>;expires=60


    sip:user:password@host:port;header-parameters
    sip:user:password@host:port;uri-parameters?headers-parameters
	<sip:user:password@host:port;uri-parameters>headers-parameters
	display name <user:password@host:port;uri-parameters>headers-parameters
	"display name" <user:password@host:port;uri-parameters>headers-parameters
*/

type SipContact struct {
	UriType []byte // Type of URI sip, sips, tel etc
	Name    []byte // Named portion of URI
	User    []byte // User part
	Host    []byte // Host part
	Port    []byte // Port number
	Tran    []byte // Transport
	Qval    []byte // Q Value
	Expires []byte // Expires
	Maddr   []byte
	Tgrp    []byte // tgrp parameter
	Src     []byte // Full source if needed
}

func NewSipContact(uriType, name, user, host, port, tran, qval, expires, maddr, src string) SipContact {
	return SipContact{
		UriType: []byte(uriType),
		Name:    []byte(name),
		User:    []byte(user),
		Host:    []byte(host),
		Port:    []byte(port),
		Tran:    []byte(tran),
		Qval:    []byte(qval),
		Expires: []byte(expires),
		Maddr:   []byte(maddr),
		Src:     []byte(src),
	}
}

// <sip:+441304380808;tgrp=PST_IB2_B2BUA_04_01;trunk-context=hex-mgc-01.gamma.uktel.org.uk@10.123.128.137:5060;user=phone>
// <sip:novatm.co.uk:5060;transport=udp;maddr=10.124.133.15>;q=0.5
// "bob" <sip:bob@127.0.0.1:65223;ob>
// "alice" <sip:alice@192.168.7.219:5060;transport=UDP>
// <sip:+44111223344@10.0.0.2:5060>

// find the <> and split the string into 2 parts inside and outside the <>

// inside the <> split the string by ; and parse the parameters

func parseSipContact(v []byte, out *SipContact) error {

	var idx int

	// Init the output area
	out.UriType = nil
	out.Name = nil
	out.User = nil
	out.Host = nil
	out.Port = nil
	out.Tran = nil
	out.Qval = nil
	out.Expires = nil
	out.Maddr = nil
	out.Tgrp = nil
	out.Src = nil

	// Keep the source line if needed
	if keep_src {
		out.Src = v
	}

	// parse out the display name if present
	if idx = bytes.IndexByte(v, byte('<')); idx > -1 {
		out.Name = bytes.TrimSpace(v[:idx])
		out.Name = bytes.Trim(out.Name, `"`)
		v = v[idx:]
	}

	// if < is present, then it is encapsulated form
	if idx = bytes.IndexByte(v, byte('<')); idx > -1 {

		endIdx := bytes.IndexByte(v, byte('>')) // index of closing angle bracket
		if endIdx == -1 {
			return errors.New("missing closing angle bracket")
		}

		// outside the <> parse the parameters
		outsideParams := v[endIdx+1:]
		if len(outsideParams) > 0 {
			parseSipContactHeaderParams(outsideParams, out)
		}

		// Extract the URI part
		uriPart := v[idx+1 : endIdx]
		var insideParams []byte
		semiIdx := bytes.IndexByte(uriPart, byte(';')) // index of semicolon

		// If a semicolon is found, split the URI part and parameters part
		if semiIdx > -1 {
			insideParams = uriPart[semiIdx:]
			uriPart = uriPart[:semiIdx]
		}

		// Parse parameters inside the angle brackets
		if len(insideParams) > 0 {
			parseSipContactHeaderParams(insideParams, out)
		}

		// Parse the URI part
		parseUri(uriPart, out)

	} else { // Non-encapsulated form
		parseUri(v, out)
		parseSipContactHeaderParams(v, out)
	}

	return nil

}

func parseUri(uriPart []byte, out *SipContact) {
	// Find the URI scheme (sip or sips)
	if idx := bytes.Index(uriPart, []byte("sip:")); idx > -1 {
		out.UriType = uriPart[idx : idx+3]
		uriPart = uriPart[idx+4:]
	} else if idx := bytes.Index(uriPart, []byte("sips:")); idx > -1 {
		out.UriType = uriPart[idx : idx+4]
		uriPart = uriPart[idx+5:]
	} else {
		return
	}

	// Find if userinfo is present, denoted by @
	if idx := bytes.IndexByte(uriPart, byte('@')); idx > -1 {
		out.User = uriPart[:idx]
		uriPart = uriPart[idx+1:]

	} else if idx := bytes.IndexByte(uriPart, byte(':')); idx == -1 {
		// If no @ or : is found, the entire part is the user
		out.User = uriPart
		return
	}

	// Trim off the password from the user section
	if idx := bytes.IndexByte(out.User, byte(':')); idx > -1 {
		out.User = out.User[:idx]
	}

	// Apply fix for a non-compliant UA
	if idx := bytes.IndexByte(out.User, byte(';')); idx > -1 {
		out.User = out.User[:idx]
	}

	// If uri contains : Split the remaining part into host and port
	hostPort := bytes.Split(uriPart, []byte(":"))
	if len(hostPort) == 2 {
		out.Host = hostPort[0]
		out.Port = hostPort[1]
	} else {
		out.Host = uriPart
	}

}

func parseSipContactHeaderParams(paramsPart []byte, out *SipContact) {
	paramsPart = bytes.TrimSpace(paramsPart)

	// if ; is the first character, remove it
	if len(paramsPart) > 0 && paramsPart[0] == ';' {
		paramsPart = paramsPart[1:]
	}

	// Split the parameters by semicolon
	params := bytes.Split(paramsPart, []byte(";"))

	for _, param := range params {
		if len(param) == 0 {
			continue
		}

		// Check for ";q="
		if bytes.HasPrefix(param, []byte("q=")) {
			out.Qval = param[2:]
			continue
		}

		// Check for ";expires="
		if bytes.HasPrefix(param, []byte("expires=")) {
			out.Expires = param[8:]
			continue
		}

		// Check for ";transport="
		if bytes.HasPrefix(param, []byte("transport=")) {
			out.Tran = param[10:]
			continue
		}

		// Check for ";maddr="
		if bytes.HasPrefix(param, []byte("maddr=")) {
			out.Maddr = param[6:]
			continue
		}

		// Check for ";tgrp="
		if bytes.HasPrefix(param, []byte("tgrp=")) {
			out.Tgrp = param[5:]
			continue
		}

		// Check for ";trunk-context=" split host and port
		if bytes.HasPrefix(param, []byte("trunk-context=")) {
			uid := bytes.Split(param[14:], []byte("@"))
			if len(uid) == 2 {
				hostPort := bytes.Split(uid[1], []byte(":"))
				if len(hostPort) == 2 {
					out.Host = hostPort[0]
					out.Port = hostPort[1]
				}
			}
			continue
		}

	}
}
