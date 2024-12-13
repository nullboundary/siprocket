package siprocket

import (
	"fmt"
	"strings"
	"testing"
)

func Test_sipMarshal_test(t *testing.T) {

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
		Auth: SipVal{
			Value: []byte(`Digest username="bob", realm="127.0.0.1", nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", uri="sip:127.0.0.1", response="6629fae49393a05397450978507c4ef1", algorithm=MD5`),
			Src:   []byte(`Digest username="bob", realm="127.0.0.1", nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", uri="sip:127.0.0.1", response="6629fae49393a05397450978507c4ef1", algorithm=MD5`),
		},
		Allow: SipVal{
			Value: []byte("PRACK, INVITE, ACK, BYE, CANCEL, UPDATE, INFO, SUBSCRIBE, NOTIFY, REFER, MESSAGE, OPTIONS"),
			Src:   []byte("PRACK, INVITE, ACK, BYE, CANCEL, UPDATE, INFO, SUBSCRIBE, NOTIFY, REFER, MESSAGE, OPTIONS"),
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
		printByteDifferences(normExp, normOut)
	}

}

func printByteDifferences(expected, actual string) {
	fmt.Println("Expected bytes:")
	for i := 0; i < len(expected); i++ {
		fmt.Printf("%d ", expected[i])
	}
	fmt.Println("\nActual bytes:")
	for i := 0; i < len(actual); i++ {
		fmt.Printf("%d ", actual[i])
	}
	fmt.Println()
}
