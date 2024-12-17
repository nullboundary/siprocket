package siprocket

import (
	"encoding/json"
	"reflect"
	"testing"
)

func Test_sipParse_Nonsense(t *testing.T) {

	var out, exp SipMsg

	msg := `asdf`
	exp = SipMsg{
		Req: SipReq{
			Method:     []byte(nil),
			UriType:    []byte(nil),
			StatusCode: []byte(nil),
			StatusDesc: []byte(nil),
			User:       []byte(nil),
			Host:       []byte(nil),
			Port:       []byte(nil),
			UserType:   []byte(nil),
			Src:        []byte("asdf"),
		},
		From: SipFrom{
			UriType: []byte(nil),
			Name:    []byte(nil),
			User:    []byte(nil),
			Host:    []byte(nil),
			Port:    []byte(nil),
			Params:  [][]byte(nil),
			Tag:     []byte(nil),
			Src:     []byte(nil),
		},
		To: SipTo{
			UriType: []byte(nil),
			Name:    []byte(nil),
			User:    []byte(nil),
			Host:    []byte(nil),
			Port:    []byte(nil),
			Params:  [][]byte(nil),
			Tag:     []byte(nil),
			Src:     []byte(nil),
		},
		Contact: SipContact{
			UriType: []byte(nil),
			Name:    []byte(nil),
			User:    []byte(nil),
			Host:    []byte(nil),
			Port:    []byte(nil),
			Tran:    []byte(nil),
			Qval:    []byte(nil),
			Expires: []byte(nil),
			Src:     []byte(nil),
		},
		Via: []SipVia{},
		Cseq: SipCseq{
			Id:     []byte(nil),
			Method: []byte(nil),
			Src:    []byte(nil),
		},
		Ua: SipVal{
			Value: []byte(nil),
			Src:   []byte(nil),
		},
		Exp: SipVal{
			Value: []byte(nil),
			Src:   []byte(nil),
		},
		Allow: SipAllow{
			Methods: [][]byte(nil),
		},
		Auth: SipAuth{
			Digest:    []byte(nil),
			Username:  []byte(nil),
			Realm:     []byte(nil),
			Nonce:     []byte(nil),
			Uri:       []byte(nil),
			Qop:       []byte(nil),
			Nc:        []byte(nil),
			Cnonce:    []byte(nil),
			Response:  []byte(nil),
			Algorithm: []byte(nil),
		},
		MaxFwd: SipVal{
			Value: []byte(nil),
			Src:   []byte(nil),
		},
		CallId: SipVal{
			Value: []byte(nil),
			Src:   []byte(nil),
		},
		ContType: SipVal{
			Value: []byte(nil),
			Src:   []byte(nil),
		},
		ContLen: SipVal{
			Value: []byte(nil),
			Src:   []byte(nil),
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

	out = Parse([]byte(msg))
	eq := reflect.DeepEqual(out, exp)
	if !eq {
		exp, _ := json.MarshalIndent(exp, "", "  ")
		out, _ := json.MarshalIndent(out, "", "  ")
		t.Errorf("Mismatch:\nExpected:\n%s\nGot:\n%s", exp, out)
	}
}

func Test_sipParse_invite(t *testing.T) {

	var out, exp SipMsg

	msg := `INVITE sip:123456789@testcompany.com SIP/2.0
Via: SIP/2.0/WSS testcompany.com;branch=z0GMslasdf
Max-Forwards: 69
To: <sip:123456789@testcompany.com>
From: <sip:PersonA_PC_123456789@testcompany.com>;tag=ujpedsvksh
Call-ID: kasdf023l4qklaansdf02
CSeq: 8918 INVITE
X-gamma-public-ip: 127.0.0.1
Contact: <sip:PersonA_PC_123456789@testcompany.com;ob>
Content-Type: application/sdp
Allow: INVITE,ACK,CANCEL,BYE,UPDATE,MESSAGE,OPTIONS,REFER,INFO,NOTIFY
Supported: ice,replaces,outbound
User-Agent: softphone-desktop
Content-Length: 1245
	
m=audio 51268 RTP/AVP 111 9 8 101
c=IN IP4 127.0.0.1
a=rtpmap:111 opus/48000/2
a=rtpmap:9 G722/8000`
	exp = SipMsg{
		Req: SipReq{
			Method:     []byte("INVITE"),
			UriType:    []byte("sip"),
			StatusCode: []byte(nil),
			StatusDesc: []byte(nil),
			User:       []byte("123456789"),
			Host:       []byte("testcompany.com"),
			Port:       []byte(nil),
			UserType:   []byte(nil),
			Src:        []byte("INVITE sip:123456789@testcompany.com SIP/2.0"),
		},
		From: SipFrom{
			UriType: []byte("sip"),
			Name:    []byte(nil),
			User:    []byte("PersonA_PC_123456789"),
			Host:    []byte("testcompany.com"),
			Port:    []byte(nil),
			Params:  [][]byte(nil),
			Tag:     []byte("ujpedsvksh"),
			Src:     []byte("<sip:PersonA_PC_123456789@testcompany.com>;tag=ujpedsvksh"),
		},
		To: SipTo{
			UriType: []byte("sip"),
			Name:    []byte(nil),
			User:    []byte("123456789"),
			Host:    []byte("testcompany.com"),
			Port:    []byte(nil),
			Params:  [][]byte(nil),
			Tag:     []byte(nil),
			Src:     []byte("<sip:123456789@testcompany.com>"),
		},
		Contact: SipContact{
			UriType: []byte("sip"),
			Name:    []byte(nil),
			User:    []byte("PersonA_PC_123456789"),
			Host:    []byte("testcompany.com"),
			Port:    []byte(nil),
			Tran:    []byte(nil),
			Qval:    []byte(nil),
			Expires: []byte(nil),
			Src:     []byte("<sip:PersonA_PC_123456789@testcompany.com;ob>"),
		},
		Via: []SipVia{
			{
				Trans:  "wss",
				Host:   []byte("testcompany.com"),
				Port:   []byte(nil),
				Branch: []byte("z0GMslasdf"),
				Rport:  []byte(nil),
				Maddr:  []byte(nil),
				Ttl:    []byte(nil),
				Rcvd:   []byte(nil),
				Src:    []byte("SIP/2.0/WSS testcompany.com;branch=z0GMslasdf"),
			},
		},
		Cseq: SipCseq{
			Id:     []byte("8918"),
			Method: []byte("INVITE"),
			Src:    []byte("8918 INVITE"),
		},
		Ua: SipVal{
			Value: []byte("softphone-desktop"),
			Src:   []byte("softphone-desktop"),
		},
		Exp: SipVal{
			Value: []byte(nil),
			Src:   []byte(nil),
		},
		MaxFwd: SipVal{
			Value: []byte("69"),
			Src:   []byte("69"),
		},
		CallId: SipVal{
			Value: []byte("kasdf023l4qklaansdf02"),
			Src:   []byte("kasdf023l4qklaansdf02"),
		},
		ContType: SipVal{
			Value: []byte("application/sdp"),
			Src:   []byte("application/sdp"),
		},
		Allow: SipAllow{
			Methods: [][]byte{[]byte("INVITE"), []byte("ACK"), []byte("CANCEL"), []byte("BYE"), []byte("UPDATE"), []byte("MESSAGE"), []byte("OPTIONS"), []byte("REFER"), []byte("INFO"), []byte("NOTIFY")},
			Src:     []byte("INVITE,ACK,CANCEL,BYE,UPDATE,MESSAGE,OPTIONS,REFER,INFO,NOTIFY"),
		},
		ContLen: SipVal{
			Value: []byte("1245"),
			Src:   []byte("1245"),
		},
		XGammaIP: SipVal{
			Value: []byte("127.0.0.1"),
			Src:   []byte("127.0.0.1"),
		},
		Sdp: SdpMsg{
			MediaDesc: SdpMediaDesc{
				MediaType: []byte("audio"),
				Port:      []byte("51268"),
				Proto:     []byte("RTP/AVP"),
				Fmt:       []byte("111 9 8 101"),
				Src:       []byte("audio 51268 RTP/AVP 111 9 8 101"),
			},
			Attrib: []SdpAttrib{
				{
					Cat: []byte("rtpmap"),
					Val: []byte("111 opus/48000/2"),
					Src: []byte("rtpmap:111 opus/48000/2"),
				},
				{
					Cat: []byte("rtpmap"),
					Val: []byte("9 G722/8000"),
					Src: []byte("rtpmap:9 G722/8000"),
				},
			},
			ConnData: SdpConnData{
				AddrType: []byte("IP4"),
				ConnAddr: []byte("127.0.0.1"),
				Src:      []byte("IN IP4 127.0.0.1"),
			},
		},
	}
	out = Parse([]byte(msg))
	eq := reflect.DeepEqual(out, exp)
	if !eq {
		t.Errorf("Mismatch:\nExpected:\n%s\nGot:\n%s", exp, out)
	}
}

func Test_sipParse_invite2(t *testing.T) {

	var out, exp SipMsg

	msg := `INVITE sip:8508000123456;phone-context=+44@10.0.0.1;user=phone SIP/2.0
Max-Forwards: 69
Session-Expires: 3600;refresher=uac
Min-SE: 600
Supported: 100rel,timer
To: <sip:8508000123456;phone-context=+44@10.0.0.1;user=phone>
From: <sip:+44111223344@10.0.0.2;b>;tag=123456789-131732457
P-Asserted-Identity: <sip:+441284335370@10.0.0.2:5060;user=phone>
Call-ID: 20230069-123456789-2021222324@server1.mycompany.com
CSeq: 1 INVITE
Allow: UPDATE,PRACK,INFO,NOTIFY,REGISTER,OPTIONS,BYE,INVITE,ACK,CANCEL
Via: SIP/2.0/UDP 10.0.0.2:5060;branch=saiasdofijwemropasdf
Contact: <sip:+44111223344@10.0.0.2:5060>
Content-Type: application/sdp
Accept: application/sdp
Content-Length: 250

v=0
o=server1 3487 929 IN IP4 10.0.0.2
s=sip call
c=IN IP4 10.120.204.1
t=0 0
m=audio 11484 RTP/AVP 0 8 18 101
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=fmtp:18 annexb=no
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
a=ptime:20`
	exp = SipMsg{
		Req: SipReq{
			Method:     []byte("INVITE"),
			UriType:    []byte("sip"),
			StatusCode: []byte(nil),
			StatusDesc: []byte(nil),
			User:       []byte("8508000123456"),
			Host:       []byte("10.0.0.1"),
			Port:       []byte(nil),
			UserType:   []byte("phone"),
			Src:        []byte("INVITE sip:8508000123456;phone-context=+44@10.0.0.1;user=phone SIP/2.0"),
		},
		From: SipFrom{
			UriType: []byte("sip"),
			Name:    []byte(nil),
			User:    []byte("+44111223344"),
			Host:    []byte("10.0.0.2"),
			Port:    []byte(nil),
			Params: [][]byte{
				[]byte("b"),
			},
			Tag: []byte("123456789-131732457"),
			Src: []byte("<sip:+44111223344@10.0.0.2;b>;tag=123456789-131732457"),
		},
		To: SipTo{
			UriType: []byte("sip"),
			Name:    []byte(nil),
			User:    []byte("8508000123456"),
			Host:    []byte("10.0.0.1"),
			Port:    []byte(nil),
			Params: [][]byte{
				[]byte("phone-context=+44"),
				[]byte("user=phone"),
			},
			Tag: []byte(nil),
			Src: []byte("<sip:8508000123456;phone-context=+44@10.0.0.1;user=phone>"),
		},
		Contact: SipContact{
			UriType: []byte("sip"),
			Name:    []byte(nil),
			User:    []byte("+44111223344"),
			Host:    []byte("10.0.0.2"),
			Port:    []byte("5060"),
			Tran:    []byte(nil),
			Qval:    []byte(nil),
			Expires: []byte(nil),
			Src:     []byte("<sip:+44111223344@10.0.0.2:5060>"),
		},
		Via: []SipVia{
			{
				Trans:  "udp",
				Host:   []byte("10.0.0.2"),
				Port:   []byte("5060"),
				Branch: []byte("saiasdofijwemropasdf"),
				Rport:  []byte(nil),
				Maddr:  []byte(nil),
				Ttl:    []byte(nil),
				Rcvd:   []byte(nil),
				Src:    []byte("SIP/2.0/UDP 10.0.0.2:5060;branch=saiasdofijwemropasdf"),
			},
		},
		Cseq: SipCseq{
			Id:     []byte("1"),
			Method: []byte("INVITE"),
			Src:    []byte("1 INVITE"),
		},
		Allow: SipAllow{
			Methods: [][]byte{[]byte("UPDATE"), []byte("PRACK"), []byte("INFO"), []byte("NOTIFY"), []byte("REGISTER"), []byte("OPTIONS"), []byte("BYE"), []byte("INVITE"), []byte("ACK"), []byte("CANCEL")},
			Src:     []byte("UPDATE,PRACK,INFO,NOTIFY,REGISTER,OPTIONS,BYE,INVITE,ACK,CANCEL"),
		},
		Ua: SipVal{
			Value: []byte(nil),
			Src:   []byte(nil),
		},
		Exp: SipVal{
			Value: []byte(nil),
			Src:   []byte(nil),
		},
		MaxFwd: SipVal{
			Value: []byte("69"),
			Src:   []byte("69"),
		},
		CallId: SipVal{
			Value: []byte("20230069-123456789-2021222324@server1.mycompany.com"),
			Src:   []byte("20230069-123456789-2021222324@server1.mycompany.com"),
		},
		ContType: SipVal{
			Value: []byte("application/sdp"),
			Src:   []byte("application/sdp"),
		},
		ContLen: SipVal{
			Value: []byte("250"),
			Src:   []byte("250"),
		},
		XGammaIP: SipVal{
			Value: []byte(nil),
			Src:   []byte(nil),
		},
		Sdp: SdpMsg{
			Version: []byte("0"),
			Origin:  []byte("server1 3487 929 IN IP4 10.0.0.2"),
			Session: []byte("sip call"),
			Timing:  []byte("0 0"),
			MediaDesc: SdpMediaDesc{
				MediaType: []byte("audio"),
				Port:      []byte("11484"),
				Proto:     []byte("RTP/AVP"),
				Fmt:       []byte("0 8 18 101"),
				Src:       []byte("audio 11484 RTP/AVP 0 8 18 101"),
			},
			Attrib: []SdpAttrib{
				{
					Cat: []byte("rtpmap"),
					Val: []byte("0 PCMU/8000"),
					Src: []byte("rtpmap:0 PCMU/8000"),
				},
				{
					Cat: []byte("rtpmap"),
					Val: []byte("8 PCMA/8000"),
					Src: []byte("rtpmap:8 PCMA/8000"),
				},
				{
					Cat: []byte("fmtp"),
					Val: []byte("18 annexb=no"),
					Src: []byte("fmtp:18 annexb=no"),
				},
				{
					Cat: []byte("rtpmap"),
					Val: []byte("101 telephone-event/8000"),
					Src: []byte("rtpmap:101 telephone-event/8000"),
				},
				{
					Cat: []byte("fmtp"),
					Val: []byte("101 0-15"),
					Src: []byte("fmtp:101 0-15"),
				},
				{
					Cat: []byte("ptime"),
					Val: []byte("20"),
					Src: []byte("ptime:20"),
				},
			},
			ConnData: SdpConnData{
				AddrType: []byte("IP4"),
				ConnAddr: []byte("10.120.204.1"),
				Src:      []byte("IN IP4 10.120.204.1"),
			},
		},
	}
	out = Parse([]byte(msg))
	eq := reflect.DeepEqual(out, exp)
	if !eq {
		t.Errorf("Mismatch:\nExpected:\n%s\nGot:\n%s", exp, out)
	}
}

func Test_sipParse_GenericTest(t *testing.T) {

	var out, exp SipMsg

	msg := `INVITE sip:8660000101304799968;phone-context=+44@10.120.38.17:5060;user=phone SIP/2.0
	Via: SIP/2.0/UDP 10.123.128.137:5060;branch=z9hG4bK-60c7c042-3-803569663
	To: <sip:8660000101304799968;phone-context=+44@10.120.38.17;user=phone>
	From: <sip:+441304380808@10.123.128.137;user=phone>;tag=14906060
	Call-ID: 1623703618-524272678@3
	CSeq: 1 INVITE
	Max-Forwards: 70
	Contact: <sip:+441304380808;tgrp=PST_IB2_B2BUA_04_01;trunk-context=hex-mgc-01.gamma.uktel.org.uk@10.123.128.137:5060;user=phone>
	Expires: 330
	Allow: INVITE, ACK, BYE, CANCEL, INFO, PRACK, REFER, SUBSCRIBE, NOTIFY, UPDATE
	Accept: application/sdp
	P-Asserted-Identity: <sip:+441304380808@10.123.128.137;user=phone>
	Content-Length: 0
	`
	exp = SipMsg{
		Req: SipReq{
			Method:     []byte("INVITE"),
			UriType:    []byte("sip"),
			StatusCode: []byte(nil),
			StatusDesc: []byte(nil),
			User:       []byte("8660000101304799968"),
			Host:       []byte("10.120.38.17"),
			Port:       []byte("5060"),
			UserType:   []byte("phone"),
			Src:        []byte("INVITE sip:8660000101304799968;phone-context=+44@10.120.38.17:5060;user=phone SIP/2.0"),
		},
		From: SipFrom{
			UriType: []byte("sip"),
			Name:    []byte(nil),
			User:    []byte("+441304380808"),
			Host:    []byte("10.123.128.137"),
			Port:    []byte(nil),
			Params:  [][]byte{[]byte("user=phone")},
			Tag:     []byte("14906060"),
			Src:     []byte("<sip:+441304380808@10.123.128.137;user=phone>;tag=14906060"),
		},
		To: SipTo{
			UriType: []byte("sip"),
			Name:    []byte(nil),
			User:    []byte("8660000101304799968"),
			Host:    []byte("10.120.38.17"),
			Port:    []byte(nil),
			Params:  [][]byte{[]byte("phone-context=+44"), []byte("user=phone")},
			Tag:     []byte(nil),
			Src:     []byte("<sip:8660000101304799968;phone-context=+44@10.120.38.17;user=phone>"),
		},
		Contact: SipContact{
			UriType: []byte("sip"),
			Name:    []byte(nil),
			User:    []byte("+441304380808"),
			Host:    []byte("10.123.128.137"),
			Port:    []byte("5060"),
			Tran:    []byte(nil),
			Expires: []byte(nil),
			Src:     []byte("<sip:+441304380808;tgrp=PST_IB2_B2BUA_04_01;trunk-context=hex-mgc-01.gamma.uktel.org.uk@10.123.128.137:5060;user=phone>"),
		},
		Via: []SipVia{
			{
				Trans:  "udp",
				Host:   []byte("10.123.128.137"),
				Port:   []byte("5060"),
				Branch: []byte("z9hG4bK-60c7c042-3-803569663"),
				Src:    []byte("SIP/2.0/UDP 10.123.128.137:5060;branch=z9hG4bK-60c7c042-3-803569663"),
			},
		},
		Cseq: SipCseq{
			Id:     []byte("1"),
			Method: []byte("INVITE"),
			Src:    []byte("1 INVITE"),
		},
		Ua: SipVal{
			Value: []byte(nil),
			Src:   []byte(nil),
		},
		Exp: SipVal{
			Value: []byte("330"),
			Src:   []byte("330"),
		},
		Allow: SipAllow{
			Methods: [][]byte{[]byte("INVITE"), []byte("ACK"), []byte("BYE"), []byte("CANCEL"), []byte("INFO"), []byte("PRACK"), []byte("REFER"), []byte("SUBSCRIBE"), []byte("NOTIFY"), []byte("UPDATE")},
			Src:     []byte("INVITE, ACK, BYE, CANCEL, INFO, PRACK, REFER, SUBSCRIBE, NOTIFY, UPDATE"),
		},
		MaxFwd: SipVal{
			Value: []byte("70"),
			Src:   []byte("70"),
		},
		CallId: SipVal{
			Value: []byte("1623703618-524272678@3"),
			Src:   []byte("1623703618-524272678@3"),
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
	out = Parse([]byte(msg))
	eq := reflect.DeepEqual(out, exp)
	if !eq {
		t.Errorf("Mismatch:\nExpected:\n%s\nGot:\n%s", exp, out)
	}
}

func Test_sipParse_302Test(t *testing.T) {

	var out, exp SipMsg

	msg := `SIP/2.0 302 Moved temporarily
	Via:SIP/2.0/UDP 10.124.148.3;branch=z9hG4bKbbab.f2349cdf1b0788f23b2648c6829b675d.0
	From:<sip:ali.winter_PC_01173747677@novatm.co.uk>;tag=atpbkpq86t
	To:<sip:ali.winter_PC_01173747677@novatm.co.uk>;tag=990900480-1661244511483
	Call-ID:rpuvgblrlonejfnjc7jcjh
	CSeq:6 REGISTER
	Contact:<sip:novatm.co.uk:5060;transport=udp;maddr=10.124.133.15>;q=0.5
	Content-Length:0	
	`
	exp = SipMsg{
		Req: SipReq{
			Method:     []byte(nil),
			UriType:    []byte(nil),
			StatusCode: []byte("302"),
			StatusDesc: []byte("Moved temporarily"),
			User:       []byte(nil),
			Host:       []byte(nil),
			Port:       []byte(nil),
			UserType:   []byte(nil),
			Src:        []byte("SIP/2.0 302 Moved temporarily"),
		},
		From: SipFrom{
			UriType: []byte("sip"),
			Name:    []byte(nil),
			User:    []byte("ali.winter_PC_01173747677"),
			Host:    []byte("novatm.co.uk"),
			Port:    []byte(nil),
			Params:  [][]byte(nil),
			Tag:     []byte("atpbkpq86t"),
			Src:     []byte("<sip:ali.winter_PC_01173747677@novatm.co.uk>;tag=atpbkpq86t"),
		},
		To: SipTo{
			UriType: []byte("sip"),
			Name:    []byte(nil),
			User:    []byte("ali.winter_PC_01173747677"),
			Host:    []byte("novatm.co.uk"),
			Port:    []byte(nil),
			Params:  [][]byte(nil),
			Tag:     []byte("990900480-1661244511483"),
			Src:     []byte("<sip:ali.winter_PC_01173747677@novatm.co.uk>;tag=990900480-1661244511483"),
		},
		Contact: SipContact{
			UriType: []byte("sip"),
			Name:    []byte(nil),
			User:    []byte(nil),
			Host:    []byte("novatm.co.uk"),
			Port:    []byte("5060"),
			Tran:    []byte("udp"),
			Qval:    []byte("0.5"),
			Expires: []byte(nil),
			Maddr:   []byte("10.124.133.15"),
			Src:     []byte("<sip:novatm.co.uk:5060;transport=udp;maddr=10.124.133.15>;q=0.5"),
		},
		Via: []SipVia{
			{
				Trans:  "udp",
				Host:   []byte("10.124.148.3"),
				Port:   []byte(nil),
				Branch: []byte("z9hG4bKbbab.f2349cdf1b0788f23b2648c6829b675d.0"),
				Rport:  []byte(nil),
				Maddr:  []byte(nil),
				Ttl:    []byte(nil),
				Rcvd:   []byte(nil),
				Src:    []byte("SIP/2.0/UDP 10.124.148.3;branch=z9hG4bKbbab.f2349cdf1b0788f23b2648c6829b675d.0"),
			},
		},
		Cseq: SipCseq{
			Id:     []byte("6"),
			Method: []byte("REGISTER"),
			Src:    []byte("6 REGISTER"),
		},
		Ua: SipVal{
			Value: []byte(nil),
			Src:   []byte(nil),
		},
		Exp: SipVal{
			Value: []byte(nil),
			Src:   []byte(nil),
		},
		MaxFwd: SipVal{
			Value: []byte(nil),
			Src:   []byte(nil),
		},
		CallId: SipVal{
			Value: []byte("rpuvgblrlonejfnjc7jcjh"),
			Src:   []byte("rpuvgblrlonejfnjc7jcjh"),
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
	out = Parse([]byte(msg))
	eq := reflect.DeepEqual(out, exp)
	if !eq {
		t.Errorf("Mismatch:\nExpected:\n%s\nGot:\n%s", exp, out)
	}
}

func Test_sipParse_AuthTest(t *testing.T) {

	var out, exp SipMsg

	msg := `REGISTER sip:127.0.0.1 SIP/2.0
	Via: SIP/2.0/UDP 127.0.0.1:65223;rport;branch=z9hG4bKPjHathatTav6jR5ACPe7Ab-PkpHiNfno21
	Max-Forwards: 70
	From: "bob" <sip:bob@127.0.0.1>;tag=kMql7AuzTfBakV9lw99afTj1kFk2aMqU
	To: "bob" <sip:bob@127.0.0.1>
	Call-ID: 8U1evs7JtnhJDYRlRvDBcouvJiNod4CT
	CSeq: 6643 REGISTER
	User-Agent: Telephone 1.6
	Contact: "bob" <sip:bob@127.0.0.1:65223;ob>
	Expires: 300
	Authorization: Digest username="bob", realm="127.0.0.1", nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", uri="sip:127.0.0.1", response="6629fae49393a05397450978507c4ef1", algorithm=MD5
	Allow: PRACK, INVITE, ACK, BYE, CANCEL, UPDATE, INFO, SUBSCRIBE, NOTIFY, REFER, MESSAGE, OPTIONS
	Content-Length:  0
	`
	exp = SipMsg{
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
			// Qval:    [][]byte{[]byte("ob")},
			Expires: []byte(nil),
			Src:     []byte(`"bob" <sip:bob@127.0.0.1:65223;ob>`),
		},
		Via: []SipVia{
			{
				Trans:  "udp",
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
		Allow: SipAllow{
			Methods: [][]byte{[]byte("PRACK"), []byte("INVITE"), []byte("ACK"), []byte("BYE"), []byte("CANCEL"), []byte("UPDATE"), []byte("INFO"), []byte("SUBSCRIBE"), []byte("NOTIFY"), []byte("REFER"), []byte("MESSAGE"), []byte("OPTIONS")},
			Src:     []byte("PRACK, INVITE, ACK, BYE, CANCEL, UPDATE, INFO, SUBSCRIBE, NOTIFY, REFER, MESSAGE, OPTIONS"),
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
			Src:       []byte(`Digest username="bob", realm="127.0.0.1", nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", uri="sip:127.0.0.1", response="6629fae49393a05397450978507c4ef1", algorithm=MD5`),
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

	out = Parse([]byte(msg))
	eq := reflect.DeepEqual(out, exp)
	if !eq {
		t.Errorf("Mismatch:\nExpected:\n%s\nGot:\n%s", exp, out)
	}
}

func Test_sipParse_200OKTest(t *testing.T) {

	var out, exp SipMsg

	msg := `SIP/2.0 200 OK
Via: SIP/2.0/udp 127.0.0.1:65223;branch=z9hG4bKPjS7DclXXdEgN6Bz9TwtlXYn2Y1CX9MXQV;rport=
From: "bob" <sip:bob@127.0.0.1>;tag=dbnZLsDcuJ64mJQxdkaW0PCRkEOmWYwc
To: "alice" <sip:alice@127.0.0.1>;tag=z9hG4bK1811891bb91f7ef8
Contact: "alice" <sip:alice@192.168.7.219:5060;transport=UDP>
Call-ID: A6LbNFTZyRDzORcdsBtwmGN1h4KIuYPI
CSeq: 5023 CANCEL
User-Agent: Telephone 1.6
Expires: 3600
Content-Length: 0
`
	exp = SipMsg{
		Req: NewSipReq("", "", "", "", "", "", "200", "OK", "SIP/2.0 200 OK"),
		Via: []SipVia{
			NewSipVia("udp", "127.0.0.1", "65223", "z9hG4bKPjS7DclXXdEgN6Bz9TwtlXYn2Y1CX9MXQV", "", "SIP/2.0/udp 127.0.0.1:65223;rport;branch=z9hG4bKPjS7DclXXdEgN6Bz9TwtlXYn2Y1CX9MXQV"),
		},
		From:    NewSipFrom("sip", "bob", "bob", "127.0.0.1", "", "dbnZLsDcuJ64mJQxdkaW0PCRkEOmWYwc", `"bob" <sip:bob@127.0.0.1>;tag=dbnZLsDcuJ64mJQxdkaW0PCRkEOmWYwc`),
		To:      NewSipTo("sip", "alice", "alice", "127.0.0.1", "", "z9hG4bK1811891bb91f7ef8", `"alice" <sip:alice@127.0.0.1>;tag=z9hG4bK1811891bb91f7ef8`),
		Contact: NewSipContact("sip", "alice", "alice", "192.168.7.219", "5060", "UDP", "", "", "", `"alice" <sip:alice@192.168.7.219:5060;transport=UDP>`),
		CallId:  NewSipVal("A6LbNFTZyRDzORcdsBtwmGN1h4KIuYPI", "A6LbNFTZyRDzORcdsBtwmGN1h4KIuYPI"),
		Cseq:    NewSipCseq("5023", "CANCEL", "5023 CANCEL"),
		Ua:      NewSipVal("Telephone 1.6", "Telephone 1.6"),
		Exp:     NewSipVal("3600", "3600"),
		ContLen: NewSipVal("0", "0"),
	}

	out = Parse([]byte(msg))
	eq := reflect.DeepEqual(out, exp)
	if !eq {
		t.Errorf("Mismatch:\nExpected:\n%s\nGot:\n%s", exp, out)
	}

}

func (s SipReq) MarshalJSON() ([]byte, error) {

	return json.Marshal(&struct {
		Method     string // Sip Method eg INVITE etc
		UriType    string // Type of URI sip, sips, tel etc
		StatusCode string // Status Code eg 100
		StatusDesc string // Status Code Description eg trying
		User       string // User part
		Host       string // Host part
		Port       string // Port number
		UserType   string // User Type
		Src        string // Full source if needed
	}{
		string(s.Method),
		string(s.UriType),
		string(s.StatusCode),
		string(s.StatusDesc),
		string(s.User),
		string(s.Host),
		string(s.Port),
		string(s.UserType),
		string(s.Src),
	})
}

func (s SipFrom) MarshalJSON() ([]byte, error) {

	return json.Marshal(&struct {
		UriType string   // Type of URI sip, sips, tel etc
		Name    string   // Named portion of URI
		User    string   // User part
		Host    string   // Host part
		Port    string   // Port number
		Params  []string // Array of URI prams
		Tag     string   // Tag
		Src     string   // Full source if needed
	}{
		string(s.UriType),
		string(s.Name),
		string(s.User),
		string(s.Host),
		string(s.Port),
		custConv(s.Params),
		string(s.Tag),
		string(s.Src),
	})
}

func custConv(oldArr [][]byte) (newArr []string) {

	for _, v := range oldArr {
		newArr = append(newArr, string(v))
	}
	return
}

func BenchmarkParse(b *testing.B) {
	sipMessage := []byte(`REGISTER sip:127.0.0.1 SIP/2.0
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

`)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = Parse(sipMessage)
	}
}
