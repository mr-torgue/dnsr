package utils

import (
	"strings"

	"github.com/miekg/dns"
)

// GetValue returns the value of RR.
// FIXME is there a better way of doing this? Technically, I think it is only used for NS/A/AAAA/CNAME records
func GetValue(rr dns.RR) string {
	switch t := rr.(type) {
	case *dns.SOA:
		return ToLowerFQDN(t.Ns)
	case *dns.NS:
		return ToLowerFQDN(t.Ns)
	case *dns.CNAME:
		return ToLowerFQDN(t.Target)
	case *dns.A:
		return t.A.String()
	case *dns.AAAA:
		return t.AAAA.String()
	case *dns.TXT:
		return strings.Join(t.Txt, " ")
	default:
		fields := strings.Fields(rr.String())
		if len(fields) >= 4 {
			return strings.Join(fields[4:], " ")
		}
	}
	return ""
}	