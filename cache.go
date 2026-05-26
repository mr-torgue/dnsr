// Package utils provides helper functions and definitions for the cache, including
// DNS record validation statuses, cached RRSet entries, and key generation.
package dnsr

import (
	"encoding/xml"
	"fmt"
	"hash/fnv"
	"os"
	"strings"
	"time"

	"github.com/miekg/dns"
)

type ValidationStatus int

// rename this so it starts with DNSSEC
const (
	Indeterminate ValidationStatus = iota
	Secure
	Insecure
	Bogus
)

// TrustAnchor XML structure for root-anchors.xml
type TrustAnchor struct {
	XMLName   xml.Name `xml:"TrustAnchor"`
	Zone      string   `xml:"Zone"`
	KeyDigest []struct {
		Tag        uint16 `xml:"KeyTag"`
		Algorithm  uint8  `xml:"Algorithm"`
		DigestType uint8  `xml:"DigestType"`
		Digest     string `xml:"Digest"`
		PublicKey  string `xml:"PublicKey"`
	} `xml:"KeyDigest"`
}

// Entry represents a cached RRSet (CoreDNS style)
type Entry struct {
	Name       string
	Type       uint16
	Status     ValidationStatus
	Rcode      int
	Records    []dns.RR
	Signatures []dns.RR
	TTL        uint32
	Expires    time.Time
}

func Key(name string, qtype uint16) uint64 {
	h := fnv.New64a()
	h.Write([]byte(dns.CanonicalName(name)))
	h.Write([]byte(dns.TypeToString[qtype]))
	return h.Sum64()
}

// LoadRootmap loads the NS, A, AAAA, and DS (if dnssec is enabled) RR for the rootzone.
func LoadRootmap(rootzonefile string, rootanchorfile string, dnssec bool) map[uint64]([]dns.RR) {
	rootmap := make(map[uint64][]dns.RR)

	// load the rootzone records
	content, err := os.ReadFile(rootzonefile)
	if err != nil {
		fmt.Printf("Error reading rootfile: %v\n", err)
		return nil
	}
	contentStr := string(content)
	zp := dns.NewZoneParser(strings.NewReader(contentStr), "", "")
	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		k := Key(rr.Header().Name, rr.Header().Rrtype)
		rootmap[k] = append(rootmap[k], rr)
	}
	if err := zp.Err(); err != nil {
		panic(err)
	}

	// load the dnssec records if dnssec is enabled
	if dnssec {
		f, err := os.Open(rootanchorfile)
		if err != nil {
			fmt.Printf("Root anchors file not found")
			return nil
		}
		defer f.Close()

		var ta TrustAnchor
		if err := xml.NewDecoder(f).Decode(&ta); err != nil {
			fmt.Printf("Failed to decode root anchors")
			return nil
		}

		for _, kd := range ta.KeyDigest {
			ds := &dns.DS{
				Hdr: dns.RR_Header{
					Name:   ".",
					Rrtype: dns.TypeDS,
					Class:  dns.ClassINET,
					Ttl:    86400,
				},
				KeyTag:     kd.Tag,
				Algorithm:  kd.Algorithm,
				DigestType: kd.DigestType,
				Digest:     kd.Digest,
			}
			k := Key(".", dns.TypeDS)
			rootmap[k] = append(rootmap[k], ds)
		}
	}
	return rootmap
}
