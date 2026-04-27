package utils

import (
	"testing"

	"github.com/coredns/coredns/plugin/test"
  	"github.com/stretchr/testify/assert"
	"github.com/miekg/dns"
)

func TestValue(t *testing.T) {
	tests := []struct {
        name string
        rr dns.RR
		expected string 
    }{
        {"Should return CNAME", test.CNAME("invent.example.org.		1781	IN	CNAME	leptone.example.org."), "leptone.example.org."},
        {"Should return IPv4", test.A("leptone.example.org.	1781	IN	A	195.201.182.103"), "195.201.182.103"},
        {"Should reutrn RRSIG", test.RRSIG("invent.example.org.		1781	IN	RRSIG	CNAME 8 3 1800 20201012085750 20200912082613 57411 example.org. ijSv5FmsNjFviBcOFwQgqjt073lttxTTNqkno6oMa3DD3kC+"), "CNAME 8 3 1800 20201012085750 20200912082613 57411 example.org. ijSv5FmsNjFviBcOFwQgqjt073lttxTTNqkno6oMa3DD3kC+"},
        {"Should return IPv6", test.AAAA("example.com.  IN  AAAA  2001:0db8:85a3:0000:0000:8a2e:0370:7334"), "2001:db8:85a3::8a2e:370:7334"},
        {"Should return CNAME", test.CNAME("store.example.com. IN  CNAME  example.com."), "example.com."},
        {"Should return MX", test.MX("example.com.  IN  MX  10  mail1.example.com."), "10 mail1.example.com."},
        {"Should return TXT", test.TXT("example.com.  IN  TXT  \"v=spf1 include:_spf.example.com ~all\""), "v=spf1 include:_spf.example.com ~all"},
    }

    for _, tt := range tests {// Loop over each test case
        t.Run(tt.name, func(t *testing.T) {// Run each case as a subtest
			v := GetValue(tt.rr)
  			assert.Equal(t, tt.expected, v, tt.name)
        })
    }
}