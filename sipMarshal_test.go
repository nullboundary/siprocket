package siprocket

import (
	"strings"
	"testing"
)

func Test_sipMarshal_Register_test(t *testing.T) {

	msgData := SipMsg{
		Req: SipReq{
			Method:     []byte("REGISTER"),
			UriType:    []byte("sip"),
			StatusCode: []byte(nil),
			StatusDesc: []byte(nil),
			User:       []byte(nil),
			Host:       []byte("127.0.0.1"),
			Port:       []byte(nil),
			UserType:   []byte(nil),
			Src:        []byte("REGISTER sip:127.0.0.1 SIP/2.0"),
		},
		From: SipFrom{
			UriType: []byte("sip"),
			Name:    []byte("bob"),
			User:    []byte("bob"),
			Host:    []byte("127.0.0.1"),
			Port:    []byte(nil),
			Params:  [][]byte(nil),
			Tag:     []byte("kMql7AuzTfBakV9lw99afTj1kFk2aMqU"),
			Src:     []byte(`"bob" <sip:bob@127.0.0.1>;tag=kMql7AuzTfBakV9lw99afTj1kFk2aMqU`),
		},
		To: SipTo{
			UriType: []byte("sip"),
			Name:    []byte("bob"),
			User:    []byte("bob"),
			Host:    []byte("127.0.0.1"),
			Port:    []byte(nil),
			Params:  [][]byte(nil),
			Tag:     []byte(nil),
			Src:     []byte(`"bob" <sip:bob@127.0.0.1>`),
		},
		Contact: SipContact{
			UriType: []byte("sip"),
			Name:    []byte("bob"),
			User:    []byte("bob"),
			Host:    []byte("127.0.0.1"),
			Port:    []byte("65223"),
			Tran:    []byte(nil),
			Qval:    []byte("ob"),
			Expires: []byte(nil),
			Src:     []byte(`"bob" <sip:bob@127.0.0.1:65223;ob>`),
		},
		Via: []SipVia{
			{
				Trans:  "UDP",
				Host:   []byte("127.0.0.1"),
				Port:   []byte("65223"),
				Branch: []byte("z9hG4bKPjHathatTav6jR5ACPe7Ab-PkpHiNfno21"),
				Rport:  []byte(nil),
				Src:    []byte("SIP/2.0/UDP 127.0.0.1:65223;rport;branch=z9hG4bKPjHathatTav6jR5ACPe7Ab-PkpHiNfno21"),
			},
		},
		Cseq: SipCseq{
			Id:     []byte("6643"),
			Method: []byte("REGISTER"),
			Src:    []byte("6643 REGISTER"),
		},
		Ua: SipVal{
			Value: []byte("Telephone 1.6"),
			Src:   []byte("Telephone 1.6"),
		},
		Exp: SipVal{
			Value: []byte("300"),
			Src:   []byte("300"),
		},
		Auth: SipAuth{
			Digest:    []byte("Digest"),
			Username:  []byte("bob"),
			Realm:     []byte("127.0.0.1"),
			Nonce:     []byte("dcd98b7102dd2f0e8b11d0f600bfb0c093"),
			Uri:       []byte("sip:127.0.0.1"),
			Qop:       []byte(nil),
			Nc:        []byte(nil),
			Cnonce:    []byte(nil),
			Response:  []byte("6629fae49393a05397450978507c4ef1"),
			Algorithm: []byte("MD5"),
		},
		Allow: SipAllow{
			Methods: [][]byte{[]byte("PRACK"), []byte("INVITE"), []byte("ACK"), []byte("BYE"), []byte("CANCEL"), []byte("UPDATE"), []byte("INFO"), []byte("SUBSCRIBE"), []byte("NOTIFY"), []byte("REFER"), []byte("MESSAGE"), []byte("OPTIONS")},
			Src:     []byte("PRACK, INVITE, ACK, BYE, CANCEL, UPDATE, INFO, SUBSCRIBE, NOTIFY, REFER, MESSAGE, OPTIONS"),
		},
		MaxFwd: SipVal{
			Value: []byte("70"),
			Src:   []byte("70"),
		},
		CallId: SipVal{
			Value: []byte("8U1evs7JtnhJDYRlRvDBcouvJiNod4CT"),
			Src:   []byte("8U1evs7JtnhJDYRlRvDBcouvJiNod4CT"),
		},
		ContType: SipVal{
			Value: []byte(nil),
			Src:   []byte(nil),
		},
		ContLen: SipVal{
			Value: []byte("0"),
			Src:   []byte("0"),
		},
		XGammaIP: SipVal{
			Value: []byte(nil),
			Src:   []byte(nil),
		},
		Sdp: SdpMsg{
			MediaDesc: SdpMediaDesc{
				MediaType: []byte(nil),
				Port:      []byte(nil),
				Proto:     []byte(nil),
				Fmt:       []byte(nil),
				Src:       []byte(nil),
			},
			Attrib: []SdpAttrib{},
			ConnData: SdpConnData{
				AddrType: []byte(nil),
				ConnAddr: []byte(nil),
				Src:      []byte(nil),
			},
		},
	}

	exp := `REGISTER sip:127.0.0.1 SIP/2.0
Via: SIP/2.0/UDP 127.0.0.1:65223;rport;branch=z9hG4bKPjHathatTav6jR5ACPe7Ab-PkpHiNfno21
From: "bob" <sip:bob@127.0.0.1>;tag=kMql7AuzTfBakV9lw99afTj1kFk2aMqU
To: "bob" <sip:bob@127.0.0.1>
Contact: "bob" <sip:bob@127.0.0.1:65223;ob>
Call-ID: 8U1evs7JtnhJDYRlRvDBcouvJiNod4CT
CSeq: 6643 REGISTER
Max-Forwards: 70
User-Agent: Telephone 1.6
Expires: 300
Authorization: Digest username="bob", realm="127.0.0.1", nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", uri="sip:127.0.0.1", response="6629fae49393a05397450978507c4ef1", algorithm=MD5
Allow: PRACK, INVITE, ACK, BYE, CANCEL, UPDATE, INFO, SUBSCRIBE, NOTIFY, REFER, MESSAGE, OPTIONS
Content-Length: 0

`

	out := Marshal(&msgData)
	// Normalize line endings to \n for comparison
	normExp := strings.ReplaceAll(exp, "\r\n", "\n")
	normOut := strings.ReplaceAll(out, "\r\n", "\n")

	if normOut != normExp {
		t.Errorf("Mismatch:\nExpected:\n%q\nGot:\n%q", normExp, normOut)
	}

}

func Test_sipMarshal_Invite_test(t *testing.T) {

	msgData := SipMsg{
		Req:     NewSipReq("INVITE", "sip", "1001", "127.0.0.1", "", "", "", "", "INVITE sip:1001@127.0.0.1 SIP/2.0"),
		From:    NewSipFrom("sip", "bob", "bob", "127.0.0.1", "", "dbnZLsDcuJ64mJQxdkaW0PCRkEOmWYwc", `"bob" <sip:bob@127.0.0.1>;tag=dbnZLsDcuJ64mJQxdkaW0PCRkEOmWYwc`),
		To:      NewSipTo("sip", "1001", "1001", "127.0.0.1", "", "", `"1001" <sip:1001@127.0.0.1>;tag=`),
		Contact: NewSipContact("sip", "bob", "bob", "127.0.0.1", "65223", "", "", "", "", `"bob" <sip:bob@127.0.0.1:65223>`),
		Via: []SipVia{
			NewSipVia("UDP", "127.0.0.1", "65223", "z9hG4bKPjS7DclXXdEgN6Bz9TwtlXYn2Y1CX9MXQV", "", "SIP/2.0/UDP 127.0.0.1:65223;rport;branch=z9hG4bKPjS7DclXXdEgN6Bz9TwtlXYn2Y1CX9MXQV"),
		},
		Cseq:     NewSipCseq("5023", "INVITE", "5023 INVITE"),
		Ua:       NewSipVal("Telephone 1.6", "Telephone 1.6"),
		ContType: NewSipVal("application/sdp", "application/sdp"),
		ContLen:  NewSipVal("433", "433"),
		MaxFwd:   NewSipVal("70", "70"),
		CallId:   NewSipVal("A6LbNFTZyRDzORcdsBtwmGN1h4KIuYPI", "A6LbNFTZyRDzORcdsBtwmGN1h4KIuYPI"),
		Sdp: SdpMsg{
			Version:   []byte("0"),
			Origin:    []byte("- 4000 4000 IN IP4 192.168.7.219"),
			Session:   []byte("-"),
			Timing:    []byte("0 0"),
			MediaDesc: NewSdpMediaDesc("audio", "4000", "RTP/AVP", "96 9 8 0 101 102", "m=audio 4000 RTP/AVP 96 9 8 0 101 102"),
			Attrib: []SdpAttrib{
				NewSdpAttrib("X-nat", "0", "a=X-nat:0"),
				NewSdpAttrib("rtcp", "4001 IN IP4 127.0.0.1", "a=rtcp:4001 IN IP4 127.0.0.1"),
				NewSdpAttrib("sendrecv", "", "a=sendrecv"),
				NewSdpAttrib("rtpmap", "96 opus/48000/2", "a=rtpmap:96 opus/48000/2"),
				NewSdpAttrib("fmtp", "96 useinbandfec=1", "a=fmtp:96 useinbandfec=1"),
				NewSdpAttrib("rtpmap", "9 G722/8000", "a=rtpmap:9 G722/8000"),
				NewSdpAttrib("rtpmap", "8 PCMA/8000", "a=rtpmap:8 PCMA/8000"),
				NewSdpAttrib("rtpmap", "0 PCMU/8000", "a=rtpmap:0 PCMU/8000"),
				NewSdpAttrib("rtpmap", "101 telephone-event/48000", "a=rtpmap:101 telephone-event/48000"),
				NewSdpAttrib("fmtp", "101 0-16", "a=fmtp:101 0-16"),
				NewSdpAttrib("rtpmap", "102 telephone-event/8000", "a=rtpmap:102 telephone-event/8000"),
				NewSdpAttrib("fmtp", "102 0-16", "a=fmtp:102 0-16"),
				NewSdpAttrib("ssrc", "335007840 cname:4ef325353d0fe311", "a=ssrc:335007840 cname:4ef325353d0fe311"),
			},
			ConnData: NewSdpConnData("IN", "IP4 192.168.7.219", "c=IN IP4 192.168.7.219"),
		},
	}

	exp := `INVITE sip:1001@127.0.0.1 SIP/2.0
Via: SIP/2.0/UDP 127.0.0.1:65223;rport;branch=z9hG4bKPjS7DclXXdEgN6Bz9TwtlXYn2Y1CX9MXQV
From: "bob" <sip:bob@127.0.0.1>;tag=dbnZLsDcuJ64mJQxdkaW0PCRkEOmWYwc
To: "1001" <sip:1001@127.0.0.1>;tag=
Contact: "bob" <sip:bob@127.0.0.1:65223>
Call-ID: A6LbNFTZyRDzORcdsBtwmGN1h4KIuYPI
CSeq: 5023 INVITE
Max-Forwards: 70
User-Agent: Telephone 1.6
Content-Type: application/sdp
Content-Length: 433

v=0
o=- 4000 4000 IN IP4 192.168.7.219
s=-
t=0 0
m=audio 4000 RTP/AVP 96 9 8 0 101 102
c=IN IP4 192.168.7.219
a=X-nat:0
a=rtcp:4001 IN IP4 127.0.0.1
a=sendrecv
a=rtpmap:96 opus/48000/2
a=fmtp:96 useinbandfec=1
a=rtpmap:9 G722/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:0 PCMU/8000
a=rtpmap:101 telephone-event/48000
a=fmtp:101 0-16
a=rtpmap:102 telephone-event/8000
a=fmtp:102 0-16
a=ssrc:335007840 cname:4ef325353d0fe311
`
	out := Marshal(&msgData)
	// Normalize line endings to \n for comparison
	normExp := strings.ReplaceAll(exp, "\r\n", "\n")
	normOut := strings.ReplaceAll(out, "\r\n", "\n")

	if normOut != normExp {
		t.Errorf("Mismatch:\nExpected:\n%q\nGot:\n%q", normExp, normOut)
	}
}

func BenchmarkMarshal(b *testing.B) {
	msgData := SipMsg{
		Req: SipReq{
			Method:     []byte("REGISTER"),
			UriType:    []byte("sip"),
			StatusCode: []byte(nil),
			StatusDesc: []byte(nil),
			User:       []byte(nil),
			Host:       []byte("127.0.0.1"),
			Port:       []byte(nil),
			UserType:   []byte(nil),
			Src:        []byte("REGISTER sip:127.0.0.1 SIP/2.0"),
		},
		From: SipFrom{
			UriType: []byte("sip"),
			Name:    []byte("bob"),
			User:    []byte("bob"),
			Host:    []byte("127.0.0.1"),
			Port:    []byte(nil),
			Params:  [][]byte(nil),
			Tag:     []byte("kMql7AuzTfBakV9lw99afTj1kFk2aMqU"),
			Src:     []byte(`"bob" <sip:bob@127.0.0.1>;tag=kMql7AuzTfBakV9lw99afTj1kFk2aMqU`),
		},
		To: SipTo{
			UriType: []byte("sip"),
			Name:    []byte("bob"),
			User:    []byte("bob"),
			Host:    []byte("127.0.0.1"),
			Port:    []byte(nil),
			Params:  [][]byte(nil),
			Tag:     []byte(nil),
			Src:     []byte(`"bob" <sip:bob@127.0.0.1>`),
		},
		Contact: SipContact{
			UriType: []byte("sip"),
			Name:    []byte("bob"),
			User:    []byte("bob"),
			Host:    []byte("127.0.0.1"),
			Port:    []byte("65223"),
			Tran:    []byte(nil),
			Qval:    []byte("ob"),
			Expires: []byte(nil),
			Src:     []byte(`"bob" <sip:bob@127.0.0.1:65223;ob>`),
		},
		Via: []SipVia{
			{
				Trans:  "UDP",
				Host:   []byte("127.0.0.1"),
				Port:   []byte("65223"),
				Branch: []byte("z9hG4bKPjHathatTav6jR5ACPe7Ab-PkpHiNfno21"),
				Rport:  []byte(nil),
				Src:    []byte("SIP/2.0/UDP 127.0.0.1:65223;rport;branch=z9hG4bKPjHathatTav6jR5ACPe7Ab-PkpHiNfno21"),
			},
		},
		Cseq: SipCseq{
			Id:     []byte("6643"),
			Method: []byte("REGISTER"),
			Src:    []byte("6643 REGISTER"),
		},
		Ua: SipVal{
			Value: []byte("Telephone 1.6"),
			Src:   []byte("Telephone 1.6"),
		},
		Exp: SipVal{
			Value: []byte("300"),
			Src:   []byte("300"),
		},
		Auth: SipAuth{
			Digest:    []byte("Digest"),
			Username:  []byte("bob"),
			Realm:     []byte("127.0.0.1"),
			Nonce:     []byte("dcd98b7102dd2f0e8b11d0f600bfb0c093"),
			Uri:       []byte("sip::127.0.0.1"),
			Qop:       []byte(nil),
			Nc:        []byte(nil),
			Cnonce:    []byte(nil),
			Response:  []byte("6629fae49393a05397450978507c4ef1"),
			Algorithm: []byte("MD5"),
		},
		Allow: SipAllow{
			Methods: [][]byte{[]byte("PRACK"), []byte("INVITE"), []byte("ACK"), []byte("BYE"), []byte("CANCEL"), []byte("UPDATE"), []byte("INFO"), []byte("SUBSCRIBE"), []byte("NOTIFY"), []byte("REFER"), []byte("MESSAGE"), []byte("OPTIONS")},
			Src:     []byte("PRACK, INVITE, ACK, BYE, CANCEL, UPDATE, INFO, SUBSCRIBE, NOTIFY, REFER, MESSAGE, OPTIONS"),
		},
		MaxFwd: SipVal{
			Value: []byte("70"),
			Src:   []byte("70"),
		},
		CallId: SipVal{
			Value: []byte("8U1evs7JtnhJDYRlRvDBcouvJiNod4CT"),
			Src:   []byte("8U1evs7JtnhJDYRlRvDBcouvJiNod4CT"),
		},
		ContType: SipVal{
			Value: []byte(nil),
			Src:   []byte(nil),
		},
		ContLen: SipVal{
			Value: []byte("0"),
			Src:   []byte("0"),
		},
		XGammaIP: SipVal{
			Value: []byte(nil),
			Src:   []byte(nil),
		},
		Sdp: SdpMsg{
			MediaDesc: SdpMediaDesc{
				MediaType: []byte(nil),
				Port:      []byte(nil),
				Proto:     []byte(nil),
				Fmt:       []byte(nil),
				Src:       []byte(nil),
			},
			Attrib: []SdpAttrib{},
			ConnData: SdpConnData{
				AddrType: []byte(nil),
				ConnAddr: []byte(nil),
				Src:      []byte(nil),
			},
		},
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = Marshal(&msgData)
	}
}
