package utils

import (
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func TestGetNameAndType(t *testing.T) {
	var m *dns.Msg

	tests := []struct {
		name           string
		domain         string
		qtype          uint16
		expectedDomain string
		expectedType   uint16
	}{
		{"Valid", "ANYTHING.com", dns.TypeA, "anything.com", dns.TypeA},
		{"Invalid DNS type", "ANYTHING.com", 1234, "anything.com", 1234},
		{"Invalid name", "1ANYTHING..com.", 1234, "1anything..com.", 1234},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m = new(dns.Msg)
			m.SetQuestion(tt.domain, tt.qtype)
			domain := GetName(m)
			qtype := GetType(m)
			assert.Equal(t, tt.expectedDomain, domain, "Domain names should match")
			assert.Equal(t, tt.expectedType, qtype, "Qtypes should match")
		})
	}

}

func TestGetDo(t *testing.T) {
	m := new(dns.Msg)
	do := GetDo(m)
	assert.Equal(t, false, do, "Expected DO flag to be false")

	m = new(dns.Msg)
	opt := new(dns.OPT)
	opt.Hdr.Name = "."
	opt.Hdr.Rrtype = dns.TypeOPT
	opt.SetUDPSize(2048)
	opt.SetDo()
	m.Extra = append(m.Extra, opt)
	do = GetDo(m)
	assert.NotNil(t, m.IsEdns0(), "Expected m.IsEdns0() to not be nil")
	assert.Equal(t, true, do, "Expected DO flag to be true")

	m = new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeA)
	m.SetEdns0(4096, true)
	do = GetDo(m)
	assert.NotNil(t, m.IsEdns0(), "Expected m.IsEdns0() to not be nil")
	assert.Equal(t, true, do, "Expected DO flag to be true")

	m = new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeA)
	m.SetEdns0(4096, false)
	do = GetDo(m)
	assert.NotNil(t, m.IsEdns0(), "Expected m.IsEdns0() to not be nil")
	assert.Equal(t, false, do, "Expected DO flag to be false")
}
func TestCreateErrorResponse(t *testing.T) {
	tests := []struct {
		name string // description of this test case
		// Named input parameters for target function.
		qname string
		qtype uint16
		rcode int
	}{
		{"test folmer.info", "folmer.info", dns.TypeA, dns.RcodeServerFailure},
		{"test sidn.nl", "sidn.nl", dns.TypeNS, dns.RcodeServerFailure},
		{"test github.com", "github.com", dns.TypeMX, dns.RcodeServerFailure},
		{"test blabla.github.com", "blabla.github.com", dns.TypeMX, dns.RcodeNameError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CreateErrorResponse(tt.qname, tt.qtype, tt.rcode)
			assert.Equal(t, tt.qname, got.Question[0].Name, "names should match")
			assert.Equal(t, tt.qtype, got.Question[0].Qtype, "types should match")
			assert.Equal(t, tt.rcode, got.Rcode, "rcodes should match")

		})
	}
}
