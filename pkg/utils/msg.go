package utils

import (
	"strings"

	"github.com/miekg/dns"
)

// GetName returns the name of the first question.
// copied from https://github.com/coredns/coredns/blob/master/request/request.go#L275
func GetName(msg *dns.Msg) string {
	if msg == nil || len(msg.Question) == 0 {
		return "."
	}
	return strings.ToLower(dns.Name(msg.Question[0].Name).String())
}

// GetType returns the type of the first question.
// copied from https://github.com/coredns/coredns/blob/master/request/request.go#L260
func GetType(msg *dns.Msg) uint16 {
	if msg == nil || len(msg.Question) == 0 {
		return 0
	}
	return msg.Question[0].Qtype
}

// GetDo returns whether the DO flag is set (e.g. DNSSEC is enabled).
func GetDo(msg *dns.Msg) bool {
	opt := msg.IsEdns0()
	if opt == nil {
		return false
	}
	return opt.Do()
}

// CreateQuestionQuestion returns a new dns message for a given query.
func CreateQuestion(qname string, qtype string) *dns.Msg {
	dtype := dns.StringToType[qtype]
	if dtype == 0 {
		dtype = dns.TypeA
	}
	var qmsg dns.Msg
	qmsg.SetQuestion(qname, dtype)
	return &qmsg
}

// CreateResponse creates a simple response for a given qname and qtpye.
func CreateResponse(qname string, qtype uint16) *dns.Msg {
	var qmsg dns.Msg
	var rmsg = new(dns.Msg)
	qmsg.SetQuestion(qname, qtype)
	rmsg.SetReply(&qmsg)
	return rmsg
}

// CreateErrorResponse creates a simple response with Rcode = RcodeServerFailure.
func CreateErrorResponse(qname string, qtype uint16, rcode int) *dns.Msg {
	rmsg := CreateResponse(qname, qtype)
	rmsg.Rcode = rcode
	return rmsg
}
