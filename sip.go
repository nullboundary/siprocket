package siprocket

import (
	"bytes"
	"fmt"
	"strings"
)

var sip_type = 0
var keep_src = true

type SipMsg struct {
	Req      SipReq
	From     SipFrom
	To       SipTo
	Contact  SipContact
	Via      []SipVia
	Cseq     SipCseq
	Ua       SipVal
	Exp      SipVal
	Auth     SipAuth
	Allow    SipAllow
	MaxFwd   SipVal
	CallId   SipVal
	ContType SipVal
	ContLen  SipVal
	XGammaIP SipVal

	Sdp SdpMsg
}

type SdpMsg struct {
	Version   []byte
	Origin    []byte
	Session   []byte
	Timing    []byte
	MediaDesc SdpMediaDesc
	Attrib    []SdpAttrib
	ConnData  SdpConnData
}

type SipVal struct {
	Value []byte // Sip Value
	Src   []byte // Full source if needed
}

func NewSipVal(val, src string) SipVal {
	return SipVal{
		Value: []byte(val),
		Src:   []byte(src),
	}
}

func Unmarshal(v []byte) (SipMsg, error) {
	return Parse(v), nil
}

// Main parsing routine, passes by value
func Parse(v []byte) (output SipMsg) {

	// Allow multiple vias and media Attribs
	via_idx := 0
	output.Via = make([]SipVia, 0, 8)
	attr_idx := 0
	output.Sdp.Attrib = make([]SdpAttrib, 0, 8)

	lines := bytes.Split(v, []byte("\r\n"))
	if len(lines) < 2 {
		lines = bytes.Split(v, []byte("\n"))
	}

	for i, line := range lines {
		//fmt.Println(i, string(line))
		line = bytes.TrimSpace(line)
		if i == 0 {
			// For the first line parse the request
			parseSipReq(line, &output.Req)
		} else {
			// For subsequent lines split in sep (: for sip, = for sdp)
			spos, stype := indexSep(line)
			if spos > 0 && stype == ':' {
				// SIP: Break up into header and value
				lhdr := strings.ToLower(string(line[0:spos]))
				lval := bytes.TrimSpace(line[spos+1:])

				// Switch on the line header
				//fmt.Println(i, string(lhdr), string(lval))
				switch {
				case lhdr == "f" || lhdr == "from":
					parseSipFrom(lval, &output.From)
				case lhdr == "t" || lhdr == "to":
					parseSipTo(lval, &output.To)
				case lhdr == "m" || lhdr == "contact":
					parseSipContact(lval, &output.Contact)
				case lhdr == "v" || lhdr == "via":
					var tmpVia SipVia
					output.Via = append(output.Via, tmpVia)
					parseSipVia(lval, &output.Via[via_idx])
					via_idx++
				case lhdr == "i" || lhdr == "call-id":
					output.CallId.Value = lval
					output.CallId.Src = lval
				case lhdr == "c" || lhdr == "content-type":
					output.ContType.Value = lval
					output.ContType.Src = lval
				case lhdr == "content-length":
					output.ContLen.Value = lval
					output.ContLen.Src = lval
				case lhdr == "user-agent":
					output.Ua.Value = lval
					output.Ua.Src = lval
				case lhdr == "expires":
					output.Exp.Value = lval
					output.Exp.Src = lval
				case lhdr == "max-forwards":
					output.MaxFwd.Value = lval
					output.MaxFwd.Src = lval
				case lhdr == "cseq":
					parseSipCseq(lval, &output.Cseq)
				case lhdr == "authorization":
					parseSipAuthorization(lval, &output.Auth)
					output.Auth.Src = lval
				case lhdr == "allow":
					parseSipAllow(lval, &output.Allow)
					output.Allow.Src = lval
				case lhdr == "x-gamma-public-ip":
					output.XGammaIP.Value = lval
					output.XGammaIP.Src = lval
				} // End of Switch
			}
			if spos == 1 && stype == '=' {
				// SDP: Break up into header and value
				lhdr := strings.ToLower(string(line[0]))
				lval := bytes.TrimSpace(line[2:])
				// Switch on the line header
				//fmt.Println(i, spos, string(lhdr), string(lval))
				switch {
				case lhdr == "v":
					output.Sdp.Version = lval
				case lhdr == "o":
					output.Sdp.Origin = lval
				case lhdr == "s":
					output.Sdp.Session = lval
				case lhdr == "t":
					output.Sdp.Timing = lval
				case lhdr == "m":
					parseSdpMediaDesc(lval, &output.Sdp.MediaDesc)
				case lhdr == "c":
					parseSdpConnectionData(lval, &output.Sdp.ConnData)
				case lhdr == "a":
					var tmpAttrib SdpAttrib
					output.Sdp.Attrib = append(output.Sdp.Attrib, tmpAttrib)
					parseSdpAttrib(lval, &output.Sdp.Attrib[attr_idx])
					attr_idx++

				} // End of Switch

			}
		}
	}

	return
}

// Finds the first valid Seperate or notes its type
func indexSep(s []byte) (int, byte) {

	for i := 0; i < len(s); i++ {
		if s[i] == ':' {
			return i, ':'
		}
		if s[i] == '=' {
			return i, '='
		}
	}
	return -1, ' '
}

// Get a string from a slice of bytes
// Checks the bounds to avoid any range errors
func getString(sl []byte, from, to int) string {
	// Remove negative values
	if from < 0 {
		from = 0
	}
	if to < 0 {
		to = 0
	}
	// Limit if over len
	if from > len(sl) || from > to {
		return ""
	}
	if to > len(sl) {
		return string(sl[from:])
	}
	return string(sl[from:to])
}

// Get a slice from a slice of bytes
// Checks the bounds to avoid any range errors
func getBytes(sl []byte, from, to int) []byte {
	// Remove negative values
	if from < 0 {
		from = 0
	}
	if to < 0 {
		to = 0
	}
	// Limit if over len
	if from > len(sl) || from > to {
		return nil
	}
	if to > len(sl) {
		return sl[from:]
	}
	return sl[from:to]
}

// Function to print all we know about the struct in a readable format
func PrintSipStruct(data *SipMsg) {
	fmt.Println("-SIP --------------------------------")

	fmt.Println("  [REQ]")
	fmt.Println("    [UriType] =>", data.Req.UriType)
	fmt.Println("    [Method] =>", string(data.Req.Method))
	fmt.Println("    [StatusCode] =>", string(data.Req.StatusCode))
	fmt.Println("    [User] =>", string(data.Req.User))
	fmt.Println("    [Host] =>", string(data.Req.Host))
	fmt.Println("    [Port] =>", string(data.Req.Port))
	fmt.Println("    [UserType] =>", string(data.Req.UserType))
	fmt.Println("    [Src] =>", string(data.Req.Src))

	// FROM
	fmt.Println("  [FROM]")
	fmt.Println("    [UriType] =>", data.From.UriType)
	fmt.Println("    [Name] =>", string(data.From.Name))
	fmt.Println("    [User] =>", string(data.From.User))
	fmt.Println("    [Host] =>", string(data.From.Host))
	fmt.Println("    [Port] =>", string(data.From.Port))
	fmt.Println("    [Tag] =>", string(data.From.Tag))
	for _, v := range data.From.Params {
		fmt.Println("    [Params] =>", string(v))
	}
	fmt.Println("    [Src] =>", string(data.From.Src))
	// TO
	fmt.Println("  [TO]")
	fmt.Println("    [UriType] =>", data.To.UriType)
	fmt.Println("    [Name] =>", string(data.To.Name))
	fmt.Println("    [User] =>", string(data.To.User))
	fmt.Println("    [Host] =>", string(data.To.Host))
	fmt.Println("    [Port] =>", string(data.To.Port))
	fmt.Println("    [Tag] =>", string(data.To.Tag))
	for _, v := range data.To.Params {
		fmt.Println("    [Params] =>", string(v))
	}
	fmt.Println("    [Src] =>", string(data.To.Src))
	// TO
	fmt.Println("  [Contact]")
	fmt.Println("    [UriType] =>", data.Contact.UriType)
	fmt.Println("    [Name] =>", string(data.Contact.Name))
	fmt.Println("    [User] =>", string(data.Contact.User))
	fmt.Println("    [Host] =>", string(data.Contact.Host))
	fmt.Println("    [Port] =>", string(data.Contact.Port))
	fmt.Println("    [Transport] =>", string(data.Contact.Tran))
	fmt.Println("    [Q] =>", string(data.Contact.Qval))
	fmt.Println("    [Expires] =>", string(data.Contact.Expires))
	fmt.Println("    [Src] =>", string(data.Contact.Src))
	// Cseq
	fmt.Println("  [Cseq]")
	fmt.Println("    [Id] =>", string(data.Cseq.Id))
	fmt.Println("    [Method] =>", string(data.Cseq.Method))
	fmt.Println("    [Src] =>", string(data.Cseq.Src))
	// UA
	fmt.Println("  [User Agent]")
	fmt.Println("    [Value] =>", string(data.Ua.Value))
	fmt.Println("    [Src] =>", string(data.Ua.Src))
	// Exp
	fmt.Println("  [Expires]")
	fmt.Println("    [Value] =>", string(data.Exp.Value))
	fmt.Println("    [Src] =>", string(data.Exp.Src))
	// Authorization
	fmt.Println("  [Authorization]")
	// fmt.Println("    [Value] =>", string(data.Auth.Value))
	fmt.Println("    [Digest] =>", string(data.Auth.Digest))
	fmt.Println("    [Username] =>", string(data.Auth.Username))
	fmt.Println("    [Realm] =>", string(data.Auth.Realm))
	fmt.Println("    [Nonce] =>", string(data.Auth.Nonce))
	fmt.Println("    [Uri] =>", string(data.Auth.Uri))
	fmt.Println("    [Qop] =>", string(data.Auth.Qop))
	fmt.Println("    [Nc] =>", string(data.Auth.Nc))
	fmt.Println("    [Cnonce] =>", string(data.Auth.Cnonce))
	fmt.Println("    [Response] =>", string(data.Auth.Response))
	fmt.Println("    [Algorithm] =>", string(data.Auth.Algorithm))
	fmt.Println("    [Opaque] =>", string(data.Auth.Opaque))
	fmt.Println("    [Src] =>", string(data.Auth.Src))
	// MaxFwd
	fmt.Println("  [Max Forwards]")
	fmt.Println("    [Value] =>", string(data.MaxFwd.Value))
	fmt.Println("    [Src] =>", string(data.MaxFwd.Src))
	// CallId
	fmt.Println("  [Call-ID]")
	fmt.Println("    [Value] =>", string(data.CallId.Value))
	fmt.Println("    [Src] =>", string(data.CallId.Src))
	// Content-Type
	fmt.Println("  [Content-Type]")
	fmt.Println("    [Value] =>", string(data.ContType.Value))
	fmt.Println("    [Src] =>", string(data.ContType.Src))
	// XGammaIP
	fmt.Println("  [XGammaIP]")
	fmt.Println("    [Value] =>", string(data.XGammaIP.Value))
	fmt.Println("    [Src] =>", string(data.XGammaIP.Src))

	// Via - Multiple
	fmt.Println("  [Via]")
	for i, via := range data.Via {
		fmt.Println("    [", i, "]")
		fmt.Println("      [Tansport] =>", via.Trans)
		fmt.Println("      [Host] =>", string(via.Host))
		fmt.Println("      [Port] =>", string(via.Port))
		fmt.Println("      [Branch] =>", string(via.Branch))
		fmt.Println("      [Rport] =>", string(via.Rport))
		fmt.Println("      [Maddr] =>", string(via.Maddr))
		fmt.Println("      [ttl] =>", string(via.Ttl))
		fmt.Println("      [Recevied] =>", string(via.Rcvd))
		fmt.Println("      [Src] =>", string(via.Src))
	}

	fmt.Println("-SDP --------------------------------")
	// Media Desc
	fmt.Println("  [MediaDesc]")
	fmt.Println("    [MediaType] =>", string(data.Sdp.MediaDesc.MediaType))
	fmt.Println("    [Port] =>", string(data.Sdp.MediaDesc.Port))
	fmt.Println("    [Proto] =>", string(data.Sdp.MediaDesc.Proto))
	fmt.Println("    [Fmt] =>", string(data.Sdp.MediaDesc.Fmt))
	fmt.Println("    [Src] =>", string(data.Sdp.MediaDesc.Src))
	// Connection Data
	fmt.Println("  [ConnData]")
	fmt.Println("    [AddrType] =>", string(data.Sdp.ConnData.AddrType))
	fmt.Println("    [ConnAddr] =>", string(data.Sdp.ConnData.ConnAddr))
	fmt.Println("    [Src] =>", string(data.Sdp.ConnData.Src))

	// Attribs - Multiple
	fmt.Println("  [Attrib]")
	for i, attr := range data.Sdp.Attrib {
		fmt.Println("    [", i, "]")
		fmt.Println("      [Cat] =>", string(attr.Cat))
		fmt.Println("      [Val] =>", string(attr.Val))
		fmt.Println("      [Src] =>", string(attr.Src))
	}
	fmt.Println("-------------------------------------")

}

const (
	FIELD_NULL = iota
	FIELD_BASE
	FIELD_VALUE
	FIELD_NAME
	FIELD_NAMEQ
	FIELD_USER
	FIELD_HOST
	FIELD_PORT
	FIELD_TAG
	FIELD_ID
	FIELD_METHOD
	FIELD_TRAN
	FIELD_BRANCH
	FIELD_RPORT
	FIELD_MADDR
	FIELD_TTL
	FIELD_REC
	FIELD_EXPIRES
	FIELD_Q
	FIELD_USERTYPE
	FIELD_STATUS
	FIELD_STATUSDESC

	FIELD_DIGEST
	FIELD_REALM
	FIELD_DOMAIN
	FIELD_QOP
	FIELD_NONCE
	FIELD_OPAQUE
	FIELD_STALE
	FIELD_ALGORITHM

	FIELD_USERNAME
	FIELD_URI
	FIELD_RESPONSE
	FIELD_NC
	FIELD_CNONCE

	FIELD_ADDRTYPE
	FIELD_CONNADDR
	FIELD_MEDIA
	FIELD_PROTO
	FIELD_FMT
	FIELD_CAT

	FIELD_IGNORE = 255
)
