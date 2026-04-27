package utils

import (
	"strings"

	"github.com/miekg/dns"
)

// copied from https://github.com/coredns/coredns/blob/master/request/request.go#L275 
func GetName(msg *dns.Msg) string {
	if msg == nil || len(msg.Question) == 0 {
		return "."
	}
	return strings.ToLower(dns.Name(msg.Question[0].Name).String())
}

// copied from https://github.com/coredns/coredns/blob/master/request/request.go#L260
func GetType(msg *dns.Msg) uint16 {
	if msg == nil || len(msg.Question) == 0 {
		return 0
	}
	return msg.Question[0].Qtype
}

func GetDo(msg *dns.Msg) bool {
	opt := msg.IsEdns0()
	if opt == nil {
		return false
	}
	return opt.Do()
}

// createCreateQuestionQuestion returns a new dns message for a given query.
func CreateQuestion(qname string, qtype string) (*dns.Msg) {
	dtype := dns.StringToType[qtype]
	if dtype == 0 {
		dtype = dns.TypeA
	}
	var qmsg dns.Msg
	qmsg.SetQuestion(qname, dtype)
	return &qmsg
}