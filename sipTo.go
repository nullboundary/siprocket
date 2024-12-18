package siprocket

import (
	"bytes"
	"errors"
)

// Parses a single line that is in the format of a to line, v
// Also requires a pointer to a struct of type SipTo to write output to
// RFC 3261 - https://www.ietf.org/rfc/rfc3261.txt - 8.1.1.2 To

type SipTo struct {
	UriType []byte   // Type of URI sip, sips, tel etc
	Name    []byte   // Named portion of URI
	User    []byte   // User part
	Host    []byte   // Host part
	Port    []byte   // Port number
	Params  [][]byte // Arrray of URI prams
	Tag     []byte   // Tag
	Src     []byte   // Full source if needed
}

func NewSipTo(uriType, name, user, host, port, tag, src string) SipTo {
	return SipTo{
		UriType: []byte(uriType),
		Name:    []byte(name),
		User:    []byte(user),
		Host:    []byte(host),
		Port:    []byte(port),
		Tag:     []byte(tag),
		Src:     []byte(src),
	}
}

/* Examples
sip:user:password@host:port;header-parameters
sip:user:password@host:port;uri-parameters?headers-parameters
<sip:user:password@host:port;uri-parameters>headers-parameters
display name <user:password@host:port;uri-parameters>headers-parameters
"display name" <user:password@host:port;uri-parameters>headers-parameters
*/

func parseSipTo(v []byte, out *SipTo) error {

	var idx int

	// Init the output area
	out.Name = nil
	out.User = nil
	out.Host = nil
	out.Params = nil
	out.Port = nil
	out.Tag = nil

	// Keep the source line if needed
	out.Src = v

	// Check if our uri string uses <> encapsulation
	// Although <> is not a reserved charactor so its possible we can go wrong
	// If there is a name string then encapsultion must be used.
	if idx = bytes.LastIndexByte(v, byte('>')); idx > -1 {

		// parse header parameters of the encapulated form
		parseSipToHeaderParams(v[idx:], out)
		v = v[:idx]

		if idx = bytes.LastIndexByte(v, byte('<')); idx == -1 {
			return errors.New("found ending encapsualtion > but not staring <")
		}

		// Extract the name field
		out.Name = v[:idx]

		// clean up out.Name
		out.Name = bytes.Trim(out.Name, ` `)
		out.Name = bytes.Trim(out.Name, `"`)

		v = v[idx+1:]

		// Next we'll find that method SIP(S)
		// Whilse the protocol allows the use 352 URI schema (we are only supporting sip)
		// https://www.iana.org/assignments/uri-schemes/uri-schemes.xhtml
		if idx = bytes.Index(v, []byte("sip:")); idx > -1 {
			out.UriType = v[idx : idx+3]
			v = v[idx+4:]
		} else if idx = bytes.Index(v, []byte("sips:")); idx > -1 {
			out.UriType = v[idx : idx+4]
			v = v[idx+5:]
		} else {
			return errors.New("unsupport URI-Schema found")
		}

		// Next find if userinfo is present denoted by @ (reserved charactor)
		if idx = bytes.IndexByte(v, byte('@')); idx > -1 {
			out.User = v[:idx]
			v = v[idx+1:]
		}

		// Trim of the password from the user section
		if idx = bytes.IndexByte(out.User, byte(':')); idx > -1 {
			out.User = out.User[:idx]
		}

		// Apply fix for a non complient ua
		if idx = bytes.IndexByte(out.User, byte(';')); idx > -1 {
			out.Params = append(out.Params, out.User[idx+1:])
			out.User = out.User[:idx]
		}

		// Extract the URL parameters
		// These can only be located inside the encapsulated form
		for {
			if idx = bytes.LastIndexByte(v, byte(';')); idx == -1 {
				break
			}
			out.Params = append(out.Params, v[idx+1:])
			v = v[:idx]
		}

		// remote any port
		if idx = bytes.IndexByte(v, byte(':')); idx > -1 {
			out.Port = v[idx+1:]
			v = v[:idx]
		}

		// all that is left is the host
		out.Host = v

	} else {
		// Parse header parameters of the non encapsulated form

		// Next we'll find that method SIP(S)
		// Whilse the protocol allows the use 352 URI schema (we are only supporting sip)
		// https://www.iana.org/assignments/uri-schemes/uri-schemes.xhtml
		if idx = bytes.Index(v, []byte("sip:")); idx > -1 {
			out.UriType = v[idx : idx+3]
			v = v[idx+4:]
		} else if idx = bytes.Index(v, []byte("sips:")); idx > -1 {
			out.UriType = v[idx : idx+4]
			v = v[idx+5:]
		} else {
			return errors.New("unsupport URI-Schema found")
		}

		// Next find if userinfo is present denoted by @ (reserved charactor)
		if idx = bytes.IndexByte(v, byte('@')); idx > -1 {
			out.User = v[:idx]
			v = v[idx+1:]
		}

		// Trim of the password from the user section
		if idx = bytes.IndexByte(out.User, byte(':')); idx > -1 {
			out.User = out.User[:idx]
		}

		// Apply fix for a non complient ua
		if idx = bytes.IndexByte(out.User, byte(';')); idx > -1 {
			out.Params = append(out.Params, out.User[idx+1:])
			out.User = out.User[:idx]
		}

		// In the non encapsulated the query form is possible
		if idx = bytes.LastIndexByte(v, byte('?')); idx > -1 {
			// parse header parameters
			parseSipToHeaderParams(v[idx:], out)
			v = v[:idx]
			// Extract the URL parameters
			// only available if the query form is used
			for {
				if idx = bytes.LastIndexByte(v, byte(';')); idx == -1 {
					break
				}
				out.Params = append(out.Params, v[idx+1:])
				v = v[:idx]
			}
		} else {
			// Parse header parameters
			if idx = bytes.LastIndexByte(v, byte(';')); idx > -1 {
				parseSipToHeaderParams(v[idx:], out)
				v = v[:idx]
			}
		}

		// remote any port
		if idx = bytes.IndexByte(v, byte(':')); idx > -1 {
			out.Port = v[idx+1:]
			v = v[:idx]
		}

		// all that is left is the host
		out.Host = v
	}

	return nil
}

func parseSipToHeaderParams(v []byte, out *SipTo) {
	var idx int

	for {
		if idx = bytes.LastIndexByte(v[idx:], byte(';')); idx == -1 {
			break
		}

		if len(v[idx:]) > 4 {
			if string(v[idx:idx+5]) == ";tag=" {
				out.Tag = v[idx+5:]
				return
			}
		}
		v = v[:idx]
	}
}
