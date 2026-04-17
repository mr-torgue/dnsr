package clients

import (
//	"encoding/hex"
	"fmt"
	"net"
//	"strconv"
	"strings"
//	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/idna"
)

// QueryFlags represents the various DNS query flags
type QueryFlags struct {
	AA bool // Authoritative Answer
	AD bool // Authenticated Data
	CD bool // Checking Disabled
	RD bool // Recursion Desired
	Z  bool // Reserved for future use
	DO bool // DNSSEC OK

	// EDNS0 options
	NSID    bool   // Request Name Server Identifier
	Cookie  bool   // Request DNS Cookie
	Padding bool   // Request EDNS padding for privacy
	EDE     bool   // Request Extended DNS Errors
	ECS     string // EDNS Client Subnet (e.g., "192.0.2.0/24" or "2001:db8::/32")
}

// prepareMessages takes a  DNS Question and returns the
// corresponding DNS messages for the same.
func prepareMessages(q dns.Question, flags QueryFlags, ndots int, searchList []string) []dns.Msg {
	var (
		possibleQNames = constructPossibleQuestions(q.Name, ndots, searchList)
		messages       = make([]dns.Msg, 0, len(possibleQNames))
	)

	for _, qName := range possibleQNames {
		msg := dns.Msg{}
		// generate a random id for the transaction.
		msg.Id = dns.Id()

		// Set query flags
		msg.RecursionDesired = flags.RD
		msg.AuthenticatedData = flags.AD
		msg.CheckingDisabled = flags.CD
		msg.Authoritative = flags.AA
		msg.Zero = flags.Z

		// Set EDNS0 if any EDNS options are requested
		if flags.DO || flags.NSID || flags.Cookie || flags.Padding || flags.EDE || flags.ECS != "" {
			msg.SetEdns0(4096, flags.DO)

			// Add EDNS0 options
			opt := msg.IsEdns0()
			if opt != nil {
				if flags.NSID {
					nsid := &dns.EDNS0_NSID{}
					opt.Option = append(opt.Option, nsid)
				}

				if flags.Cookie {
					cookie := &dns.EDNS0_COOKIE{}
					opt.Option = append(opt.Option, cookie)
				}

				if flags.Padding {
					padding := &dns.EDNS0_PADDING{
						Padding: make([]byte, 128), // Standard padding size
					}
					opt.Option = append(opt.Option, padding)
				}

				if flags.EDE {
					// EDE is typically returned by the server, but we can set up
					// the EDNS0 to signal we understand EDE responses
					ede := &dns.EDNS0_EDE{}
					opt.Option = append(opt.Option, ede)
				}

				if flags.ECS != "" {
					subnet, err := parseECS(flags.ECS)
					if err == nil {
						opt.Option = append(opt.Option, subnet)
					}
				}
			}
		}

		// It's recommended to only send 1 question for 1 DNS message.
		msg.Question = []dns.Question{{
			Name:   qName,
			Qtype:  q.Qtype,
			Qclass: q.Qclass,
		}}
		messages = append(messages, msg)
	}

	return messages
}

// NameList returns all of the names that should be queried based on the
// config. It is based off of go's net/dns name building, but it does not
// check the length of the resulting names.
// NOTE: It is taken from `miekg/dns/clientconfig.go: func (c *ClientConfig) NameList`
// and slightly modified.
func constructPossibleQuestions(name string, ndots int, searchList []string) []string {
	// if this domain is already fully qualified, no append needed.
	if dns.IsFqdn(name) {
		return []string{name}
	}

	// Check to see if the name has more labels than Ndots. Do this before making
	// the domain fully qualified.
	hasNdots := dns.CountLabel(name) > ndots
	// Make the domain fully qualified.
	name = dns.Fqdn(name)

	// Make a list of names based off search.
	names := []string{}

	// If name has enough dots, try that first.
	if hasNdots {
		names = append(names, name)
	}
	for _, s := range searchList {
		names = append(names, dns.Fqdn(name+s))
	}
	// If we didn't have enough dots, try after suffixes.
	if !hasNdots {
		names = append(names, name)
	}
	return names
}

// toUnicodeDomain converts a punycode domain name to Unicode.
// If conversion fails, returns the original domain name.
func toUnicodeDomain(name string) string {
	unicodeName, err := idna.ToUnicode(name)
	if err != nil {
		// If conversion fails, return original name
		return name
	}
	return unicodeName
}

// parseECS parses an EDNS Client Subnet string and returns an EDNS0_SUBNET option.
// Accepts formats like "192.0.2.0/24" or "2001:db8::/32".
func parseECS(subnet string) (*dns.EDNS0_SUBNET, error) {
	// Parse the CIDR notation
	parts := strings.Split(subnet, "/")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid ECS format: expected 'ip/prefix', got '%s'", subnet)
	}

	ip := strings.TrimSpace(parts[0])
	prefix := parts[1]

	// Parse the prefix length
	var prefixLen int
	_, err := fmt.Sscanf(prefix, "%d", &prefixLen)
	if err != nil {
		return nil, fmt.Errorf("invalid prefix length: %s", prefix)
	}

	// Parse the IP address
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return nil, fmt.Errorf("invalid IP address: %s", ip)
	}

	// Determine if it's IPv4 or IPv6
	family := uint16(1) // IPv4
	if parsedIP.To4() == nil {
		family = 2 // IPv6
	}

	return &dns.EDNS0_SUBNET{
		Code:          dns.EDNS0SUBNET,
		Family:        family,
		SourceNetmask: uint8(prefixLen),
		SourceScope:   0,
		Address:       parsedIP,
	}, nil
}

// should be a better and easier way of doing this...
func QtypeStr2Int(qtype string) (uint16) {
	switch(qtype) {
	case "A":
		return dns.TypeA
	case "AAAA":
		return dns.TypeAAAA
	case "NS":
		return dns.TypeNS
	case "MD":
		return dns.TypeMD
	case "MF":
		return dns.TypeMF
	case "CNAME":
		return dns.TypeCNAME
	case "SOA":
		return dns.TypeSOA
	case "MB":
		return dns.TypeMB
	case "MG":
		return dns.TypeMG
	case "MR":
		return dns.TypeMR
	case "NULL":
		return dns.TypeNULL
	case "PTR":
		return dns.TypePTR
	case "HINFO":
		return dns.TypeHINFO
	case "MINFO":
		return dns.TypeMINFO
	case "MX":
		return dns.TypeMX
	case "TXT":
		return dns.TypeTXT
	case "RP":
		return dns.TypeRP
	case "AFSDB":
		return dns.TypeAFSDB
	case "X25":
		return dns.TypeX25
	case "ISDN":
		return dns.TypeISDN
	case "RT":
		return dns.TypeRT
	case "NSAPPTR":
		return dns.TypeNSAPPTR
	case "SIG":
		return dns.TypeSIG
	case "KEY":
		return dns.TypeKEY
	case "PX":
		return dns.TypePX
	case "GPOS":
		return dns.TypeGPOS
	case "LOC":
		return dns.TypeLOC
	case "NXT":
		return dns.TypeNXT
	case "EID":
		return dns.TypeEID
	case "NIMLOC":
		return dns.TypeNIMLOC
	case "SRV":
		return dns.TypeSRV
	case "ATMA":
		return dns.TypeATMA
	case "NAPTR":
		return dns.TypeNAPTR
	case "KX":
		return dns.TypeKX
	case "CERT":
		return dns.TypeCERT
	case "DNAME":
		return dns.TypeDNAME
	case "OPT":
		return dns.TypeOPT
	case "APL":
		return dns.TypeAPL
	case "DS":
		return dns.TypeDS
	case "SSHFP":
		return dns.TypeSSHFP
	case "IPSECKEY":
		return dns.TypeIPSECKEY
	case "RRSIG":
		return dns.TypeRRSIG
	case "NSEC":
		return dns.TypeNSEC
	case "DNSKEY":
		return dns.TypeDNSKEY
	case "DHCID":
		return dns.TypeDHCID
	case "NSEC3":
		return dns.TypeNSEC3
	case "NSEC3PARAM":
		return dns.TypeNSEC3PARAM
	case "TLSA":
		return dns.TypeTLSA
	case "SMIMEA":
		return dns.TypeSMIMEA
	case "HIP":
		return dns.TypeHIP
	case "NINFO":
		return dns.TypeNINFO
	case "RKEY":
		return dns.TypeRKEY
	case "TALINK":
		return dns.TypeTALINK
	case "CDS":
		return dns.TypeCDS
	case "CDNSKEY":
		return dns.TypeCDNSKEY
	case "OPENPGPKEY":
		return dns.TypeOPENPGPKEY
	case "CSYNC":
		return dns.TypeCSYNC
	case "ZONEMD":
		return dns.TypeZONEMD
	case "SVCB":
		return dns.TypeSVCB
	case "HTTPS":
		return dns.TypeHTTPS
	case "SPF":
		return dns.TypeSPF
	case "UINFO":
		return dns.TypeUINFO
	case "UID":
		return dns.TypeUID
	case "GID":
		return dns.TypeGID
	case "UNSPEC":
		return dns.TypeUNSPEC
	case "NID":
		return dns.TypeNID
	case "L32":
		return dns.TypeL32
	case "L64":
		return dns.TypeL64
	case "LP":
		return dns.TypeLP
	case "EUI48":
		return dns.TypeEUI48
	case "EUI64":
		return dns.TypeEUI64
	case "NXNAME":
		return dns.TypeNXNAME
	case "URI":
		return dns.TypeURI
	case "CAA":
		return dns.TypeCAA
	case "AVC":
		return dns.TypeAVC
	case "AMTRELAY":
		return dns.TypeAMTRELAY
	case "RESINFO":
		return dns.TypeRESINFO
	case "TKEY":
		return dns.TypeTKEY
	case "TSIG":
		return dns.TypeTSIG
	case "IXFR":
		return dns.TypeIXFR
	case "AXFR":
		return dns.TypeAXFR
	case "MAILB":
		return dns.TypeMAILB
	case "MAILA":
		return dns.TypeMAILA
	case "ANY":
		return dns.TypeANY
	case "TA":
		return dns.TypeTA
	case "DLV":
		return dns.TypeDLV
	case "RESERVED":
		return dns.TypeReserved
	}
	return dns.TypeNone
}
