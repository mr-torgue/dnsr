package utils

import (
	"strings"

	"github.com/miekg/dns"
)

func GetParent(name string) (string, bool) {
	labels := dns.SplitDomainName(name)
	if labels == nil {
		return "", false
	}
	return ToLowerFQDN(strings.Join(labels[1:], ".")), true
}

func ToLowerFQDN(name string) string {
	return dns.Fqdn(strings.ToLower(name))
}
