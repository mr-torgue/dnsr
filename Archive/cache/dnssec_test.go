package cache

import (
	"testing"

	"github.com/coredns/coredns/plugin/test"
	"github.com/miekg/dns"
)

func TestFilterRRSlice(t *testing.T) {
	rrs := []dns.RR{
		test.CNAME("invent.example.org.		1781	IN	CNAME	leptone.example.org."),
		test.RRSIG("invent.example.org.		1781	IN	RRSIG	CNAME 8 3 1800 20201012085750 20200912082613 57411 example.org. ijSv5FmsNjFviBcOFwQgqjt073lttxTTNqkno6oMa3DD3kC+"),
		test.A("leptone.example.org.	1781	IN	A	195.201.182.103"),
		test.RRSIG("leptone.example.org.	1781	IN	RRSIG	A 8 3 1800 20201012093630 20200912083827 57411 example.org. eLuSOkLAzm/WIOpaZD3/4TfvKP1HAFzjkis9LIJSRVpQt307dm9WY9"),
	}

	filter1 := filterRRSlice(rrs, 0, false)
	if len(filter1) != 4 {
		t.Errorf("Expected 4 RRs after filtering, got %d", len(filter1))
	}
	rrsig := 0
	for _, f := range filter1 {
		if f.Header().Rrtype == dns.TypeRRSIG {
			rrsig++
		}
	}
	if rrsig != 2 {
		t.Errorf("Expected 2 RRSIGs after filtering, got %d", rrsig)
	}

	filter2 := filterRRSlice(rrs, 0, false)
	if len(filter2) != 4 {
		t.Errorf("Expected 4 RRs after filtering, got %d", len(filter2))
	}
	rrsig = 0
	for _, f := range filter2 {
		if f.Header().Rrtype == dns.TypeRRSIG {
			rrsig++
		}
	}
	if rrsig != 2 {
		t.Errorf("Expected 2 RRSIGs after filtering, got %d", rrsig)
	}
}
