package cache

import (
	"testing"
	"time"

	"github.com/coredns/coredns/plugin/test"
	"github.com/miekg/dns"
)

func cacheMsg(m *dns.Msg, tc test.Case) *dns.Msg {
	m.RecursionAvailable = tc.RecursionAvailable
	m.AuthenticatedData = tc.AuthenticatedData
	m.CheckingDisabled = tc.CheckingDisabled
	m.Authoritative = tc.Authoritative
	m.Rcode = tc.Rcode
	m.Truncated = tc.Truncated
	m.Answer = tc.Answer
	m.Ns = tc.Ns
	// m.Extra = tc.in.Extra don't copy Extra, because we don't care and fake EDNS0 DO with tc.Do.
	return m
}

// TestNewCache tests the creation of new caches
func TestNewCache(t *testing.T) {
    tests := []struct {// Define a struct for each test case and create a slice of them
		name string
        expire bool
        ncap int
        nttl time.Duration
        pcap int
        pttl time.Duration
    }{
        {"Test Normal", true, 123, 1, 321, 2},
        {"Test Default Values", false, 0, 0, 0, 0},
        {"Test Large Values", true, 123456, 9999999, 88880, 88833334},
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
			options := []Option{}
			if tt.expire {
				options = append(options, WithExpire())
			}
			if tt.ncap > 0 {
				options = append(options, WithNcap(tt.ncap))
			} else {
				tt.ncap = DefaultNcap
			}
			if tt.nttl > 0 {
				options = append(options, WithNttl(tt.nttl))
			} else {
				tt.nttl = DefaultNttl
			}
			if tt.pcap > 0 {
				options = append(options, WithPcap(tt.pcap))
			} else {
				tt.pcap = DefaultPcap
			}
			if tt.pttl > 0 {
				options = append(options, WithPttl(tt.pttl))
			} else {
				tt.pttl = DefaultPttl
			}
			c := NewCache(options...)


            if c.expire != tt.expire {
                t.Errorf("expire mismatch: got %t, expected %t\n", c.expire, tt.expire)
            }
            if c.ncap != tt.ncap {
                t.Errorf("ncap mismatch: got %d, expected %d\n", c.ncap, tt.ncap)
            }            
			if c.nttl != (tt.nttl * time.Second) {
                t.Errorf("nttl mismatch: got %d, expected %d\n", c.nttl, tt.nttl)
            }            
			if c.pcap != tt.pcap {
                t.Errorf("pcap mismatch: got %d, expected %d\n", c.pcap, tt.pcap)
            }            
			if c.pttl != (tt.pttl * time.Second) {
                t.Errorf("pttl mismatch: got %d, expected %d\n", c.pttl, tt.pttl)
            }
        })
    }
}
	
// TestCacheInsertion verifies the insertion of items to the cache.
func TestCacheInsertion(t *testing.T) {
	cacheTestCases := []struct {
		name        string
		out         test.Case // the expected message coming "out" of cache
		in          test.Case // the test message going "in" to cache
		shouldCache bool
	}{
		{
			name: "test ad bit cache",
			out: test.Case{
				Qname: "miek.nl.", Qtype: dns.TypeMX,
				Answer: []dns.RR{
					test.MX("miek.nl.	3600	IN	MX	1 aspmx.l.google.com."),
					test.MX("miek.nl.	3600	IN	MX	10 aspmx2.googlemail.com."),
				},
				RecursionAvailable: true,
				AuthenticatedData:  true,
			},
			in: test.Case{
				Qname: "miek.nl.", Qtype: dns.TypeMX,
				Answer: []dns.RR{
					test.MX("miek.nl.	3601	IN	MX	1 aspmx.l.google.com."),
					test.MX("miek.nl.	3601	IN	MX	10 aspmx2.googlemail.com."),
				},
				RecursionAvailable: true,
				AuthenticatedData:  true,
			},
			shouldCache: true,
		},
		{
			name: "test case sensitivity cache",
			out: test.Case{
				Qname: "miek.nl.", Qtype: dns.TypeMX,
				Answer: []dns.RR{
					test.MX("miek.nl.	3600	IN	MX	1 aspmx.l.google.com."),
					test.MX("miek.nl.	3600	IN	MX	10 aspmx2.googlemail.com."),
				},
				RecursionAvailable: true,
				AuthenticatedData:  true,
			},
			in: test.Case{
				Qname: "mIEK.nL.", Qtype: dns.TypeMX,
				Answer: []dns.RR{
					test.MX("miek.nl.	3601	IN	MX	1 aspmx.l.google.com."),
					test.MX("miek.nl.	3601	IN	MX	10 aspmx2.googlemail.com."),
				},
				RecursionAvailable: true,
				AuthenticatedData:  true,
			},
			shouldCache: true,
		},
		{
			name: "test truncated responses shouldn't cache",
			in: test.Case{
				Qname: "miek.nl.", Qtype: dns.TypeMX,
				Answer:    []dns.RR{test.MX("miek.nl.	1800	IN	MX	1 aspmx.l.google.com.")},
				Truncated: true,
			},
			shouldCache: false,
		},
		{
			name: "test dns.RcodeNameError cache",
			out: test.Case{
				Rcode: dns.RcodeNameError,
				Qname: "example.org.", Qtype: dns.TypeA,
				Ns: []dns.RR{
					test.SOA("example.org. 3600 IN	SOA	sns.dns.icann.org. noc.dns.icann.org. 2016082540 7200 3600 1209600 3600"),
				},
				RecursionAvailable: true,
			},
			in: test.Case{
				Rcode: dns.RcodeNameError,
				Qname: "example.org.", Qtype: dns.TypeA,
				Ns: []dns.RR{
					test.SOA("example.org. 3600 IN	SOA	sns.dns.icann.org. noc.dns.icann.org. 2016082540 7200 3600 1209600 3600"),
				},
				RecursionAvailable: true,
			},
			shouldCache: true,
		},
		{
			name: "test dns.RcodeServerFailure cache",
			out: test.Case{
				Rcode: dns.RcodeServerFailure,
				Qname: "example.org.", Qtype: dns.TypeA,
				Ns:                 []dns.RR{},
				RecursionAvailable: true,
			},
			in: test.Case{
				Rcode: dns.RcodeServerFailure,
				Qname: "example.org.", Qtype: dns.TypeA,
				Ns:                 []dns.RR{},
				RecursionAvailable: true,
			},
			shouldCache: true,
		},
		{
			name: "test dns.RcodeNotImplemented cache",
			out: test.Case{
				Rcode: dns.RcodeNotImplemented,
				Qname: "example.org.", Qtype: dns.TypeA,
				Ns:                 []dns.RR{},
				RecursionAvailable: true,
			},
			in: test.Case{
				Rcode: dns.RcodeNotImplemented,
				Qname: "example.org.", Qtype: dns.TypeA,
				Ns:                 []dns.RR{},
				RecursionAvailable: true,
			},
			shouldCache: true,
		},
		{
			name: "test expired RRSIG doesn't cache",
			in: test.Case{
				Qname: "miek.nl.", Qtype: dns.TypeMX,
				Do: true,
				Answer: []dns.RR{
					test.MX("miek.nl.	3600	IN	MX	1 aspmx.l.google.com."),
					test.MX("miek.nl.	3600	IN	MX	10 aspmx2.googlemail.com."),
					test.RRSIG("miek.nl.	1800	IN	RRSIG	MX 8 2 1800 20160521031301 20160421031301 12051 miek.nl. lAaEzB5teQLLKyDenatmyhca7blLRg9DoGNrhe3NReBZN5C5/pMQk8Jc u25hv2fW23/SLm5IC2zaDpp2Fzgm6Jf7e90/yLcwQPuE7JjS55WMF+HE LEh7Z6AEb+Iq4BWmNhUz6gPxD4d9eRMs7EAzk13o1NYi5/JhfL6IlaYy qkc="),
				},
				RecursionAvailable: true,
			},
			shouldCache: false,
		},
		{
			name: "test DO bit with RRSIG not expired cache",
			out: test.Case{
				Qname: "example.org.", Qtype: dns.TypeMX,
				Do: true,
				Answer: []dns.RR{
					test.MX("example.org.	3600	IN	MX	1 aspmx.l.google.com."),
					test.MX("example.org.	3600	IN	MX	10 aspmx2.googlemail.com."),
					test.RRSIG("example.org.	3600	IN	RRSIG	MX 8 2 1800 20170521031301 20170421031301 12051 miek.nl. lAaEzB5teQLLKyDenatmyhca7blLRg9DoGNrhe3NReBZN5C5/pMQk8Jc u25hv2fW23/SLm5IC2zaDpp2Fzgm6Jf7e90/yLcwQPuE7JjS55WMF+HE LEh7Z6AEb+Iq4BWmNhUz6gPxD4d9eRMs7EAzk13o1NYi5/JhfL6IlaYy qkc="),
				},
				RecursionAvailable: true,
			},
			in: test.Case{
				Qname: "example.org.", Qtype: dns.TypeMX,
				Do: true,
				Answer: []dns.RR{
					test.MX("example.org.	3600	IN	MX	1 aspmx.l.google.com."),
					test.MX("example.org.	3600	IN	MX	10 aspmx2.googlemail.com."),
					test.RRSIG("example.org.	1800	IN	RRSIG	MX 8 2 1800 20170521031301 20170421031301 12051 miek.nl. lAaEzB5teQLLKyDenatmyhca7blLRg9DoGNrhe3NReBZN5C5/pMQk8Jc u25hv2fW23/SLm5IC2zaDpp2Fzgm6Jf7e90/yLcwQPuE7JjS55WMF+HE LEh7Z6AEb+Iq4BWmNhUz6gPxD4d9eRMs7EAzk13o1NYi5/JhfL6IlaYy qkc="),
				},
				RecursionAvailable: true,
			},
			shouldCache: true,
		},
		{
			name: "test CD bit cache",
			out: test.Case{
				Rcode: dns.RcodeSuccess,
				Qname: "dnssec-failed.org.",
				Qtype: dns.TypeA,
				Answer: []dns.RR{
					test.A("dnssec-failed.org. 3600 IN	A	127.0.0.1"),
				},
				CheckingDisabled: true,
			},
			in: test.Case{
				Rcode: dns.RcodeSuccess,
				Qname: "dnssec-failed.org.",
				Answer: []dns.RR{
					test.A("dnssec-failed.org. 3600 IN	A	127.0.0.1"),
				},
				Qtype:            dns.TypeA,
				CheckingDisabled: true,
			},
			shouldCache: true,
		},
		/*{
			name: "test negative zone exception shouldn't cache",
			in: test.Case{
				Rcode: dns.RcodeNameError,
				Qname: "neg-disabled.example.org.", Qtype: dns.TypeA,
				Ns: []dns.RR{
					test.SOA("example.org. 3600 IN	SOA	sns.dns.icann.org. noc.dns.icann.org. 2016082540 7200 3600 1209600 3600"),
				},
			},
			shouldCache: false,
		},
		{
			name: "test positive zone exception shouldn't cache",
			in: test.Case{
				Rcode: dns.RcodeSuccess,
				Qname: "pos-disabled.example.org.", Qtype: dns.TypeA,
				Answer: []dns.RR{
					test.A("pos-disabled.example.org. 3600 IN	A	127.0.0.1"),
				},
			},
			shouldCache: false,
		},*/
		{
			name: "test positive zone exception with negative answer cache",
			in: test.Case{
				Rcode: dns.RcodeNameError,
				Qname: "pos-disabled.example.org.", Qtype: dns.TypeA,
				Ns: []dns.RR{
					test.SOA("example.org. 3600 IN	SOA	sns.dns.icann.org. noc.dns.icann.org. 2016082540 7200 3600 1209600 3600"),
				},
			},
			out: test.Case{
				Rcode: dns.RcodeNameError,
				Qname: "pos-disabled.example.org.", Qtype: dns.TypeA,
				Ns: []dns.RR{
					test.SOA("example.org. 3600 IN	SOA	sns.dns.icann.org. noc.dns.icann.org. 2016082540 7200 3600 1209600 3600"),
				},
			},
			shouldCache: true,
		},
		{
			name: "test negative zone exception with positive answer cache",
			in: test.Case{
				Rcode: dns.RcodeSuccess,
				Qname: "neg-disabled.example.org.", Qtype: dns.TypeA,
				Answer: []dns.RR{
					test.A("neg-disabled.example.org. 3600 IN	A	127.0.0.1"),
				},
			},
			out: test.Case{
				Rcode: dns.RcodeSuccess,
				Qname: "neg-disabled.example.org.", Qtype: dns.TypeA,
				Answer: []dns.RR{
					test.A("neg-disabled.example.org. 3600 IN	A	127.0.0.1"),
				},
			},
			shouldCache: true,
		},
		{
			name: "test root zone",
			in: test.Case{
				Rcode: dns.RcodeSuccess,
				Qname: ".", Qtype: dns.TypeNS,
				Answer: []dns.RR{
					test.NS(". 3600000 NS A.ROOT-SERVERS.NET."),
					test.NS(". 3600000 NS B.ROOT-SERVERS.NET."),
					test.NS(". 3600000 NS C.ROOT-SERVERS.NET."),
					test.NS(". 3600000 NS D.ROOT-SERVERS.NET."),
					test.NS(". 3600000 NS E.ROOT-SERVERS.NET."),
					test.NS(". 3600000 NS F.ROOT-SERVERS.NET."),
					test.NS(". 3600000 NS G.ROOT-SERVERS.NET."),
					test.NS(". 3600000 NS H.ROOT-SERVERS.NET."),
					test.NS(". 3600000 NS I.ROOT-SERVERS.NET."),
					test.NS(". 3600000 NS J.ROOT-SERVERS.NET."),
					test.NS(". 3600000 NS k.ROOT-SERVERS.NET."),
					test.NS(". 3600000 NS L.ROOT-SERVERS.NET."),
					test.NS(". 3600000 NS M.ROOT-SERVERS.NET."),
				},
			},
			out: test.Case{
				Rcode: dns.RcodeSuccess,
				Qname: ".", Qtype: dns.TypeNS,
				Answer: []dns.RR{
					test.NS(". 3600000 NS A.ROOT-SERVERS.NET."),
					test.NS(". 3600000 NS B.ROOT-SERVERS.NET."),
					test.NS(". 3600000 NS C.ROOT-SERVERS.NET."),
					test.NS(". 3600000 NS D.ROOT-SERVERS.NET."),
					test.NS(". 3600000 NS E.ROOT-SERVERS.NET."),
					test.NS(". 3600000 NS F.ROOT-SERVERS.NET."),
					test.NS(". 3600000 NS G.ROOT-SERVERS.NET."),
					test.NS(". 3600000 NS H.ROOT-SERVERS.NET."),
					test.NS(". 3600000 NS I.ROOT-SERVERS.NET."),
					test.NS(". 3600000 NS J.ROOT-SERVERS.NET."),
					test.NS(". 3600000 NS k.ROOT-SERVERS.NET."),
					test.NS(". 3600000 NS L.ROOT-SERVERS.NET."),
					test.NS(". 3600000 NS M.ROOT-SERVERS.NET."),
				},
			},
			shouldCache: true,
		},
	}
	now, _ := time.Parse(time.UnixDate, "Fri Apr 21 10:51:21 BST 2017")

	for _, tc := range cacheTestCases {
		t.Run(tc.name, func(t *testing.T) {
			c := NewCache()

			m := tc.in.Msg()
			m = cacheMsg(m, tc.in)
			c.AddWithTime(m, now)
			resp := c.Get(m)
			found := resp != nil

			if !tc.shouldCache && found {
				t.Fatalf("Cached message that should not have been cached: %s", resp.Question[0].Name)
			}
			if tc.shouldCache && !found {
				t.Fatalf("Did not cache message that should have been cached: %s. %+v", tc.name, resp)
			}

			if found {

				// TODO: If we incorporate these individual checks into the
				//       test.Header function, we can eliminate them from here.
				// Cache entries are always Authoritative.
				if resp.Authoritative != true {
					t.Error("Expected Authoritative Answer bit to be true, but was false")
				}
				if resp.AuthenticatedData != tc.out.AuthenticatedData {
					t.Errorf("Expected Authenticated Data bit to be %t, but got %t", tc.out.AuthenticatedData, resp.AuthenticatedData)
				}
				if resp.RecursionAvailable != tc.out.RecursionAvailable {
					t.Errorf("Expected Recursion Available bit to be %t, but got %t", tc.out.RecursionAvailable, resp.RecursionAvailable)
				}
				if resp.CheckingDisabled != tc.out.CheckingDisabled {
					t.Errorf("Expected Checking Disabled bit to be %t, but got %t", tc.out.CheckingDisabled, resp.CheckingDisabled)
				}

				if err := test.Header(tc.out, resp); err != nil {
					t.Logf("Cache %v", resp)
					t.Error(err)
				}
				if err := test.Section(tc.out, test.Answer, resp.Answer); err != nil {
					t.Logf("Cache %v -- %v", test.Answer, resp.Answer)
					t.Error(err)
				}
				if err := test.Section(tc.out, test.Ns, resp.Ns); err != nil {
					t.Error(err)
				}
				if err := test.Section(tc.out, test.Extra, resp.Extra); err != nil {
					t.Error(err)
				}
			}
		})
	}
}