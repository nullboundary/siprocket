package siprocket

import (
	"bytes"
	"strings"
)

type SipAllow struct {
	Methods [][]byte // List of methods
	Src     []byte   // Full source if needed
}

func parseSipAllow(v []byte, out *SipAllow) {
	// Init the output area
	out.Methods = nil
	out.Src = nil

	// Keep the source line if needed
	if keep_src {
		out.Src = v
	}

	// Split the input by commas to separate the methods
	methods := bytes.Split(v, []byte(","))

	// Loop through each method
	for _, method := range methods {
		// Trim any leading or trailing spaces
		method = bytes.TrimSpace(method)
		// Append the method to the Methods slice
		out.Methods = append(out.Methods, method)
	}
}

func MarshalSipAllow(data *SipAllow) string {
	var sb bytes.Buffer

	sb.WriteString(HEADER_ALLOW + ": ")

	for _, method := range data.Methods {
		sb.Write(method)
		sb.WriteString(", ")
	}

	result := sb.String()
	result = strings.TrimSuffix(result, ", ") // Remove the trailing comma and space
	result += ENDL

	return result
}
