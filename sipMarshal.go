package siprocket

import (
	"fmt"
	"strings"
)

const (
	HEADER_VIA            = "Via"
	HEADER_FROM           = "From"
	HEADER_TO             = "To"
	HEADER_CONTACT        = "Contact"
	HEADER_CALL_ID        = "Call-ID"
	HEADER_CSEQ           = "CSeq"
	HEADER_MAX_FORWARDS   = "Max-Forwards"
	HEADER_USER_AGENT     = "User-Agent"
	HEADER_EXPIRES        = "Expires"
	HEADER_AUTHORIZATION  = "Authorization"
	HEADER_ALLOW          = "Allow"
	HEADER_CONTENT_TYPE   = "Content-Type"
	HEADER_XGAMMA_IP      = "X-Gamma-IP"
	HEADER_CONTENT_LENGTH = "Content-Length"
	ENDL                  = "\r\n"
)

func Marshal(data *SipMsg) string {
	return SipStructToStr(data)
}

func SipStructToStr(data *SipMsg) string {
	var sb strings.Builder
	sb.Grow(512) // Pre-allocate memory for the string builder

	writeHeaders(&sb, data) // Write all headers

	return sb.String()
}

func writeHeaders(sb *strings.Builder, data *SipMsg) {
	writeRequestLine(sb, data)
	writeViaHeaders(sb, data)
	writeFromHeader(sb, data)
	writeToHeader(sb, data)
	writeContactHeader(sb, data)
	writeCallIdHeader(sb, data)
	writeCseqHeader(sb, data)
	writeMaxForwardsHeader(sb, data)
	writeUserAgentHeader(sb, data)
	writeExpiresHeader(sb, data)
	writeAuthorizationHeader(sb, data)
	writeAllowHeader(sb, data)
	writeContentTypeHeader(sb, data)
	writeXGammaIPHeader(sb, data)
	writeContentLengthAndSdpBody(sb, data)
}

// writeStatusLine writes the Status Line or Request Line to the string builder
func writeRequestLine(sb *strings.Builder, data *SipMsg) {

	// This is a response header write the Status Line
	if len(data.Req.StatusCode) > 0 {
		fmt.Fprintf(sb, "%s %s %s%s", data.Req.SipVersion, data.Req.StatusCode, data.Req.StatusDesc, ENDL)
		return
	}

	// This is a request header write the Request Line
	if data.Req.User == nil {
		fmt.Fprintf(sb, "%s sip:%s SIP/2.0%s", data.Req.Method, data.Req.Host, ENDL)
		return
	}
	fmt.Fprintf(sb, "%s sip:%s@%s SIP/2.0%s", data.Req.Method, data.Req.User, data.Req.Host, ENDL)

}

// writeViaHeaders writes the Via headers to the string builder
func writeViaHeaders(sb *strings.Builder, data *SipMsg) {
	for _, via := range data.Via {
		viaHeader := MarshalSipVia(&via)
		sb.WriteString(viaHeader)
	}
}

// writeFromHeader writes the From header to the string builder
func writeFromHeader(sb *strings.Builder, data *SipMsg) {
	if data.From.Tag != nil {
		if len(data.From.Tag) > 0 {
			fmt.Fprintf(sb, "%s: \"%s\" <sip:%s@%s>;tag=%s%s", HEADER_FROM, data.From.User, data.From.User, data.From.Host, data.From.Tag, ENDL)
		} else {
			fmt.Fprintf(sb, "%s: \"%s\" <sip:%s@%s>;tag=%s", HEADER_FROM, data.From.User, data.From.User, data.From.Host, ENDL)
		}
	} else {
		fmt.Fprintf(sb, "%s: \"%s\" <sip:%s@%s>%s", HEADER_FROM, data.From.User, data.From.User, data.From.Host, ENDL)
	}
}

// writeToHeader writes the To header to the string builder
func writeToHeader(sb *strings.Builder, data *SipMsg) {
	if data.To.Tag != nil {
		if len(data.To.Tag) > 0 {
			fmt.Fprintf(sb, "%s: \"%s\" <sip:%s@%s>;tag=%s%s", HEADER_TO, data.To.User, data.To.User, data.To.Host, data.To.Tag, ENDL)
		} else {
			fmt.Fprintf(sb, "%s: \"%s\" <sip:%s@%s>;tag=%s", HEADER_TO, data.To.User, data.To.User, data.To.Host, ENDL)
		}
	} else {
		fmt.Fprintf(sb, "%s: \"%s\" <sip:%s@%s>%s", HEADER_TO, data.To.User, data.To.User, data.To.Host, ENDL)
	}
}

// writeContactHeader writes the Contact header to the string builder
func writeContactHeader(sb *strings.Builder, data *SipMsg) {
	if string(data.Contact.Tran) != "" {
		fmt.Fprintf(sb, "%s: \"%s\" <sip:%s@%s:%s;transport=%s", HEADER_CONTACT, data.Contact.User, data.Contact.User, data.Contact.Host, data.Contact.Port, data.Contact.Tran)
	} else {
		fmt.Fprintf(sb, "%s: \"%s\" <sip:%s@%s:%s", HEADER_CONTACT, data.Contact.User, data.Contact.User, data.Contact.Host, data.Contact.Port)
	}
	if len(data.Contact.Qval) > 0 {
		sb.WriteString(";")
		for _, qval := range data.Contact.Qval {
			fmt.Fprintf(sb, "%c", qval)
		}
	}
	sb.WriteString(">" + ENDL)
}

// writeCallIdHeader writes the Call-ID header to the string builder
func writeCallIdHeader(sb *strings.Builder, data *SipMsg) {
	fmt.Fprintf(sb, "%s: %s%s", HEADER_CALL_ID, data.CallId.Value, ENDL)
}

// writeCseqHeader writes the CSeq header to the string builder
func writeCseqHeader(sb *strings.Builder, data *SipMsg) {
	fmt.Fprintf(sb, "%s: %s %s%s", HEADER_CSEQ, data.Cseq.Id, data.Cseq.Method, ENDL)
}

// writeMaxForwardsHeader writes the Max-Forwards header to the string builder
func writeMaxForwardsHeader(sb *strings.Builder, data *SipMsg) {
	if data.MaxFwd.Value != nil {
		fmt.Fprintf(sb, "%s: %s%s", HEADER_MAX_FORWARDS, data.MaxFwd.Value, ENDL)
	}
}

// writeUserAgentHeader writes the User-Agent header to the string builder
func writeUserAgentHeader(sb *strings.Builder, data *SipMsg) {
	if data.Ua.Value != nil {
		fmt.Fprintf(sb, "%s: %s%s", HEADER_USER_AGENT, data.Ua.Value, ENDL)
	}
}

// writeExpiresHeader writes the Expires header to the string builder
func writeExpiresHeader(sb *strings.Builder, data *SipMsg) {
	if data.Exp.Value != nil {
		fmt.Fprintf(sb, "%s: %s%s", HEADER_EXPIRES, data.Exp.Value, ENDL)
	}
}

// writeAuthorizationHeader writes the Authorization header to the string builder
func writeAuthorizationHeader(sb *strings.Builder, data *SipMsg) {
	if data.Auth.Digest != nil {
		sb.WriteString(MarshalSipAuth(&data.Auth))
	}
}

// writeAllowHeader writes the Allow header to the string builder
func writeAllowHeader(sb *strings.Builder, data *SipMsg) {
	if data.Allow.Methods != nil {
		sb.WriteString(MarshalSipAllow(&data.Allow))
	}
}

// writeContentTypeHeader writes the Content-Type header to the string builder
func writeContentTypeHeader(sb *strings.Builder, data *SipMsg) {
	if data.ContType.Value != nil {
		fmt.Fprintf(sb, "%s: %s%s", HEADER_CONTENT_TYPE, data.ContType.Value, ENDL)
	}
}

// writeXGammaIPHeader writes the X-Gamma-IP header to the string builder
func writeXGammaIPHeader(sb *strings.Builder, data *SipMsg) {
	if data.XGammaIP.Value != nil {
		fmt.Fprintf(sb, "%s: %s%s", HEADER_XGAMMA_IP, data.XGammaIP.Value, ENDL)
	}
}

// writeContentLengthAndSdpBody writes the Content-Length and SDP Body to the string builder
func writeContentLengthAndSdpBody(sb *strings.Builder, data *SipMsg) {
	if data.Sdp.MediaDesc.Proto == nil {
		fmt.Fprintf(sb, "%s: %d%s%s", HEADER_CONTENT_LENGTH, 0, ENDL, ENDL)
	} else {
		sdpBody := writeSdpBody(&data.Sdp)
		fmt.Fprintf(sb, "%s: %d%s%s", HEADER_CONTENT_LENGTH, len(sdpBody), ENDL, ENDL)
		sb.WriteString(sdpBody)
	}
}

// writeSdpBody converts the SDP struct to a string body
func writeSdpBody(sdp *SdpMsg) string {
	var sb strings.Builder
	sb.Grow(256) // Pre-allocate memory for the string builder

	// Write Protocol Version
	if sdp.Version != nil {
		fmt.Fprintf(&sb, "v=%s%s", sdp.Version, ENDL)
	}

	// Write Origin
	if sdp.Origin != nil {
		fmt.Fprintf(&sb, "o=%s%s", sdp.Origin, ENDL)
	}

	// Write Session Name
	if sdp.Session != nil {
		fmt.Fprintf(&sb, "s=%s%s", sdp.Session, ENDL)
	}

	if sdp.Timing != nil {
		fmt.Fprintf(&sb, "t=%s%s", sdp.Timing, ENDL)
	}

	// Write Media Description
	if sdp.MediaDesc.MediaType != nil {
		fmt.Fprintf(&sb, "m=%s %s %s %s%s", sdp.MediaDesc.MediaType, sdp.MediaDesc.Port, sdp.MediaDesc.Proto, sdp.MediaDesc.Fmt, ENDL)
	}

	// Write Connection Data
	if sdp.ConnData.AddrType != nil {
		fmt.Fprintf(&sb, "c=%s %s%s", sdp.ConnData.AddrType, sdp.ConnData.ConnAddr, ENDL)
	}

	// Write Attributes
	for _, attr := range sdp.Attrib {
		if string(attr.Val) == "" {
			fmt.Fprintf(&sb, "a=%s%s", attr.Cat, ENDL)
			continue
		}
		fmt.Fprintf(&sb, "a=%s:%s%s", attr.Cat, attr.Val, ENDL)
	}

	return sb.String()
}
