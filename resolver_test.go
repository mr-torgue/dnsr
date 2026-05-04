package dnsr

import (
	"testing"
	"time"
	"fmt"
	"strings"

	"github.com/miekg/dns"
  	"github.com/stretchr/testify/assert"
  	"github.com/stretchr/testify/require"
)

type ExpectedRR struct {
	qtype uint16
	value string
}

type TestCase struct {
	name     string
	qname    string
	qtype    uint16
	rcode    int
	expectedNrAnswers int
	expectedAnswers []ExpectedRR
	expectedNrAuth int
	expectedAuth []ExpectedRR
	expectedNrExtra int
	expectedExtra []ExpectedRR
}

type TestCaseConfig struct {
	name string
	timeout string
	expectedTimeout time.Duration
	capacity int 
	expire bool
	rootfile string
	clientType string
	clientTimeout string
	expectedClientTimeout time.Duration
	tcpRetry bool
	classicRetry bool   
	dnssec bool   
	strategy string 
	expectedStrategy string 
	testCases []TestCase
}	

func TestNewResolver(t *testing.T) {
    tests := []struct {// Define a struct for each test case and create a slice of them
		name string
		timeout string
		expectedTimeout time.Duration
		capacity int 
		expire bool
		rootfile string
		clientType string
        wantType string
		clientTimeout string
		expectedClientTimeout time.Duration
		tcpRetry bool
		classicRetry bool   
		dnssec bool   
		strategy string 
		expectedStrategy string 
    }{
        {"Test Normal Configuration", "10s", 10 * time.Second, 10000, false, "pkg/cache/testdata/named.root", "tcp", "*clients.ClassicClient", "12s", 12 * time.Second, false, false, false, "", "parallel"},
        {"Test Complex Timeouts", "10m10s", 10 * time.Minute + 10 * time.Second, 10000, false, "pkg/cache/testdata/named.root", "tcp", "*clients.ClassicClient", "1h8s", time.Hour + 8 * time.Second, false, false, false, "", "parallel"},
        {"Test Wrong Timeout Formats", "10mx10s", Timeout, 10000, false, "pkg/cache/testdata/named.root", "tcp", "*clients.ClassicClient", "1h8s", time.Hour + 8 * time.Second, false, false, false, "", "parallel"},
        {"Test Booleans", "10mx10s", Timeout, 10000, true, "pkg/cache/testdata/named.root", "tcp", "*clients.ClassicClient", "1h8s", time.Hour + 8 * time.Second, true, true, true, "", "parallel"},
        {"Test Different Client UDP", "10mx10s", Timeout, 10000, true, "pkg/cache/testdata/named.root", "udp", "*clients.ClassicClient", "1h8s", time.Hour + 8 * time.Second, true, true, true, "", "parallel"},
        {"Test Different Client QUIC", "10mx10s", Timeout, 10000, true, "pkg/cache/testdata/named.root", "doq", "*clients.DOQClient", "1h8s", time.Hour + 8 * time.Second, true, true, true, "", "parallel"},
        {"Test Different Client Non-Existing, defaults to UDP", "10mx10s", Timeout, 10000, true, "pkg/cache/testdata/custom.root", "doqt", "*clients.ClassicClient", "1h8s", time.Hour + 8 * time.Second, true, true, true, "", "parallel"},
    }
	rslvr := NewResolver()
	gotType := fmt.Sprintf("%T", rslvr.client)
	assert.NotNil(t, rslvr.logger, "Logger should not be nil")
	assert.NotNil(t, rslvr.cache, "Cache should not be nil")
	assert.NotNil(t, rslvr.rootcache, "Cache should not be nil")
	assert.NotNil(t, rslvr.client, "Client should not be nil")
	assert.Equal(t, Timeout, rslvr.timeout, "Timeout should match")
	assert.Equal(t, DefaultCapacity, rslvr.capacity, "Capacity should match")
	assert.Equal(t, DefaultExpire, rslvr.expire, "Expire should match")
	assert.Equal(t, DefaultClientType, rslvr.clientType, "ClientType should match")
	assert.Equal(t, ClientTimeout, rslvr.clientTimeout, "ClientTimeout should match")
	assert.Equal(t, DefaultTCPRetry, rslvr.tcpRetry, "TcpRetry should match")
	assert.Equal(t, DefaultClassicRetry, rslvr.classicRetry, "ClassicRetry should match")
	assert.Equal(t, DefaultDNSSEC, rslvr.dnssec, "Dnssec should match")
	assert.Equal(t, DefaultStrategy, rslvr.strategy, "Strategy should match")
	assert.Equal(t, "*clients.ClassicClient", gotType, "Types should match")

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
			rslvr = NewResolver(
				WithTimeout(tt.timeout),
				WithCapacity(tt.capacity),
				WithExpire(tt.expire),
				WithClientType(tt.clientType),
				WithClientTimeout(tt.clientTimeout),
				WithTCPRetry(tt.tcpRetry),
				WithClassicRetry(tt.classicRetry),
				WithDNSSEC(tt.dnssec),
				WithStrategy(tt.strategy),
			)
			gotType = fmt.Sprintf("%T", rslvr.client)
			// test resolver
			assert.NotNil(t, rslvr.logger, "Logger should not be nil")
			assert.NotNil(t, rslvr.cache, "Cache should not be nil")
			assert.NotNil(t, rslvr.client, "Client should not be nil")
  			assert.Equal(t, tt.expectedTimeout, rslvr.timeout, "Timeout should match")
  			assert.Equal(t, tt.capacity, rslvr.capacity, "Capacity should match")
  			assert.Equal(t, tt.expire, rslvr.expire, "Expire should match")
  			assert.Equal(t, tt.clientType, rslvr.clientType, "ClientType should match")
  			assert.Equal(t, tt.expectedClientTimeout, rslvr.clientTimeout, "ClientTimeout should match")
  			assert.Equal(t, tt.tcpRetry, rslvr.tcpRetry, "TcpRetry should match")
  			assert.Equal(t, tt.classicRetry, rslvr.classicRetry, "ClassicRetry should match")
  			assert.Equal(t, tt.dnssec, rslvr.dnssec, "Dnssec should match")
  			assert.Equal(t, tt.expectedStrategy, rslvr.strategy, "Strategy should match")
			assert.Equal(t, tt.wantType, gotType, "Types should match")
			// TODO: test client and cache in more detail
        })
    }
}

// match returns true if rr is in the expectedRRs slice
func match(rr dns.RR, expectedRRs []ExpectedRR) (bool, int) {
	for i, expectedRR := range expectedRRs {
		if expectedRR.qtype == rr.Header().Rrtype && strings.Contains(rr.String(), expectedRR.value) {
			return true, i
		}
	}
	return false, 0
}

// matchall returns true iff rrs and expectedRRs are the same
func matchall(rrs []dns.RR, expectedRRs []ExpectedRR) bool {
    matchedIndices := make(map[int]bool)
    for _, rr := range rrs {
        matched, index := match(rr, expectedRRs)
        if matched {
            if matchedIndices[index] {
                return false
            }
            matchedIndices[index] = true
        }
    }
    return len(matchedIndices) == len(expectedRRs)
}

func TestResolveMsg(t *testing.T) {

	tests := []TestCaseConfig {
		{
			name: "UDP resolver without EDNS",
			timeout: "15s",
			expectedTimeout: 15 * time.Second,
			capacity: 1000,
			expire: true,
			clientType: "udp",
			clientTimeout: "2s",
			expectedClientTimeout: 2 * time.Second,
			tcpRetry: true,
			classicRetry: true,   
			dnssec: false,
			strategy: "default",
			expectedStrategy: "",			
			testCases: []TestCase {
				{
					name: "[UDP] Client should return A record of folmer.info", 
					qname: "folmer.info", 
					qtype: dns.TypeA,
					rcode: dns.RcodeSuccess,
					expectedNrAnswers: 1,
					expectedAnswers: []ExpectedRR {
						{dns.TypeA, "65.109.0.142",},
					},
					expectedNrAuth: 0,
					expectedAuth: []ExpectedRR {},
					//expectedNrExtra: 1,
					//expectedExtra: []ExpectedRR {
					//	{dns.TypeOPT, "",},
					//},

				},
				{
					name: "[UDP] Client should return A record and CNAME record of www.github.com", 
					qname: "www.github.com", 
					qtype: dns.TypeA,
					rcode: dns.RcodeSuccess,
					expectedNrAnswers: 2,
					expectedAnswers: []ExpectedRR {
						{dns.TypeA, "4.237.22.38",},
						{dns.TypeCNAME, "github.com.",},
					},
					expectedNrAuth: 0,
					expectedAuth: []ExpectedRR {},
				},
				{
					name: "[UDP] Client should return TXT records and CNAME record of www.github.com", 
					qname: "www.github.com", 
					qtype: dns.TypeTXT,
					rcode: dns.RcodeSuccess,
					expectedNrAnswers: 21,
					expectedAnswers: []ExpectedRR {
						{dns.TypeTXT, "stripe-verification=f88ef17321660a01bab1660454192e014defa29ba7b8de9633c69d6b4912217f",},
						{dns.TypeTXT, "docusign=087098e3-3d46-47b7-9b4e-8a23028154cd",},
						{dns.TypeTXT, "TAILSCALE-xOzoDvFUzZr5YYVCQFuD",},
						{dns.TypeTXT, "krisp-domain-verification=ZlyiK7XLhnaoUQb2hpak1PLY7dFkl1WE",},
						{dns.TypeTXT, "adobe-idp-site-verification=b92c9e999aef825edc36e0a3d847d2dbad5b2fc0e05c79ddd7a16139b48ecf4b",},
						{dns.TypeTXT, "shopify-verification-code=t1YPwcmvnxZyBycaCpk1MPyWoFs72o",},
						{dns.TypeTXT, "loom-site-verification=f3787154f1154b7880e720a511ea664d",},
						{dns.TypeTXT, "atlassian-domain-verification=jjgw98AKv2aeoYFxiL/VFaoyPkn3undEssTRuMg6C/3Fp/iqhkV4HVV7WjYlVeF8",},
						{dns.TypeTXT, "facebook-domain-verification=39xu4jzl7roi7x0n93ldkxjiaarx50",},
						{dns.TypeTXT, "jamf-site-verification=XtaPNIYghF_e_xRDI8CjgQ",},
						{dns.TypeTXT, "google-site-verification=82Le34Flgtd15ojYhHlGF_6g72muSjamlMVThBOJpks",},
						{dns.TypeTXT, "00Dd0000000hHE0=1TBKg000000TN2r",},
						{dns.TypeTXT, "MS=ms58704441",},
						{dns.TypeTXT, "miro-verification=d2e174fdb00c71e0bcf58f8e58c3da2dd80dcfa9",},
						{dns.TypeTXT, "apple-domain-verification=RyQhdzTl6Z6x8ZP4",},
						{dns.TypeTXT, "calendly-site-verification=at0DQARi7IZvJtXQAWhMqpmIzpvoBNF7aam5VKKxP",},
						{dns.TypeTXT, "MS=ms44452932",},
						{dns.TypeTXT, "google-site-verification=UTM-3akMgubp6tQtgEuAkYNYLyYAvpTnnSrDMWoDR3o",},
						{dns.TypeTXT, "MS=6BF03E6AF5CB689E315FB6199603BABF2C88D805",},
						{dns.TypeTXT, "v=spf1",},
						{dns.TypeCNAME, "github.com.",},
					},
					expectedNrAuth: 0,
					expectedAuth: []ExpectedRR {},
				},
				{
					name: "[UDP] Client should return NXDOMAIN", 
					qname: "1.com", 
					qtype: dns.TypeA,
					rcode: dns.RcodeNameError,
					expectedNrAnswers: 0,
					expectedAnswers: []ExpectedRR {},
					expectedNrAuth: 0,
					expectedAuth: []ExpectedRR {},
				},
				{
					name: "[UDP] Test out-of-bailiwick", 
					qname: "pnnl.gov", 
					qtype: dns.TypeA,
					rcode: dns.RcodeSuccess,
					expectedNrAnswers: 1,
					expectedAnswers: []ExpectedRR {
						{dns.TypeA, "192.101.105.198",},
					},
					expectedNrAuth: 0,
					expectedAuth: []ExpectedRR {},
				},
				{
					name: "[UDP] Client should return TXT", 
					qname: "folmer.info", 
					qtype: dns.TypeTXT,
					rcode: dns.RcodeSuccess,
					expectedNrAnswers: 2,
					expectedAnswers: []ExpectedRR {
						{dns.TypeTXT, "v=spf1",},
						{dns.TypeTXT, "protonmail-verification=9fcd905c800df450c63a61d5585f0ad3439bc0f5",},
					},
					expectedNrAuth: 0,
					expectedAuth: []ExpectedRR {},
				},/*
				{
					name: "[UDP] Client should truncate but still work", 
					qname: "cisco.com", 
					qtype: dns.TypeTXT,
					rcode: dns.RcodeSuccess,
					expectedNrAnswers: 85,
					expectedAnswers: []ExpectedRR {}, // skip this check
					expectedNrAuth: 0,
					expectedAuth: []ExpectedRR {},
				},*/
				// test truncated
			},
		},
		{
			name: "UDP resolver with timeout issues",
			timeout: "0s",
			expectedTimeout: 0 * time.Second,
			capacity: 1000,
			expire: true,
			clientType: "udp",
			clientTimeout: "2s",
			expectedClientTimeout: 2 * time.Second,
			tcpRetry: true,
			classicRetry: true,   
			dnssec: false,
			strategy: "default",
			expectedStrategy: "",			
			testCases: []TestCase {
				{
					name: "[UDP] Client should timeout", 
					qname: "folmer.info", 
					qtype: dns.TypeA,
					rcode: dns.RcodeServerFailure,
					expectedNrAnswers: 0,
					expectedAnswers: []ExpectedRR {},
					expectedNrAuth: 0,
					expectedAuth: []ExpectedRR {},
				},
			},
		},
		{
			name: "UDP resolver with timeout issues for client",
			timeout: "15s",
			expectedTimeout: 15 * time.Second,
			capacity: 1000,
			expire: true,
			clientType: "udp",
			clientTimeout: "0s",
			expectedClientTimeout: 0 * time.Second,
			tcpRetry: true,
			classicRetry: true,   
			dnssec: false,
			strategy: "default",
			expectedStrategy: "",			
			testCases: []TestCase {
				{
					name: "[UDP] Client should timeout", 
					qname: "folmer.info", 
					qtype: dns.TypeA,
					rcode: dns.RcodeServerFailure,
					expectedNrAnswers: 0,
					expectedAnswers: []ExpectedRR {},
					expectedNrAuth: 0,
					expectedAuth: []ExpectedRR {},
				},
			},
		},
	}

	// loop over client configurations
    for _, ttconfig := range tests {
		rslvr := NewResolver(
			WithDebugLogger(),
			WithTimeout(ttconfig.timeout),
			WithCapacity(ttconfig.capacity),
			WithExpire(ttconfig.expire),
			WithClientType(ttconfig.clientType),
			WithClientTimeout(ttconfig.clientTimeout),
			WithTCPRetry(ttconfig.tcpRetry),
			WithClassicRetry(ttconfig.classicRetry),
			WithDNSSEC(ttconfig.dnssec),
			WithStrategy(ttconfig.strategy),
		)
		var (
			qmsg dns.Msg
		)

		for _, tt := range ttconfig.testCases {
			t.Run(tt.name, func(t *testing.T) {
				qmsg.SetQuestion(tt.qname, tt.qtype)
				rmsg := rslvr.ResolveMsg(&qmsg)
				fmt.Printf("rmsg: %s\n", rmsg.String())
				require.NotNil(t, rmsg, "response should not be nil") // it should always return something if qmsg != nil
				assert.Equal(t, tt.rcode, rmsg.Rcode, "rcodes should match")
				assert.Equal(t, tt.expectedNrAnswers, len(rmsg.Answer), "expected a different number of results")
				if len(tt.expectedAnswers) > 0 {
					assert.True(t, matchall(rmsg.Answer, tt.expectedAnswers), "matchall for answers failed")
				}
				if len(tt.expectedAuth) > 0 {
					assert.True(t, matchall(rmsg.Ns, tt.expectedAuth), "matchall for authoritative failed")
				}
				if len(tt.expectedExtra) > 0 {
					assert.True(t, matchall(rmsg.Extra, tt.expectedExtra), "matchall for additional failed")
				}
			})
		}
    }
}
/*
func TestMain(m *testing.M) {
	flag.Parse()
	timeout := os.Getenv("DNSR_TIMEOUT")
	if timeout != "" {
		Timeout, _ = time.ParseDuration(timeout)
	}
	if os.Getenv("DNSR_DEBUG") != "" {
		DebugLogger = os.Stderr
	}
	os.Exit(m.Run())
}

func TestWithCache(t *testing.T) {
	r := NewResolver(WithCache(99))
	st.Expect(t, r.cache.capacity, 99)
}

func TestWithDialer(t *testing.T) {
	d := &net.Dialer{}
	r := NewResolver(WithDialer(d))
	st.Expect(t, r.dialer, d)
}

func TestWithExpiry(t *testing.T) {
	r := NewResolver(WithExpiry())
	st.Expect(t, r.expire, true)
}

func TestWithTimeout(t *testing.T) {
	r := NewResolver(WithTimeout(99 * time.Second))
	st.Expect(t, r.timeout, 99*time.Second)
}

func TestNewExpiring(t *testing.T) {
	r := NewExpiring(42)
	st.Expect(t, r.cache.capacity, 42)
	st.Expect(t, r.expire, true)
}

func TestNewExpiringWithTimeout(t *testing.T) {
	r := NewExpiringWithTimeout(42, 99*time.Second)
	st.Expect(t, r.cache.capacity, 42)
	st.Expect(t, r.timeout, 99*time.Second)
	st.Expect(t, r.expire, true)
}

func TestNewExpiry(t *testing.T) {
	r := NewResolver(WithExpiry())
	st.Expect(t, r.expire, true)
}

func TestSimple(t *testing.T) {
	r := NewResolver()
	_, err := r.ResolveErr("1.com", "")
	st.Expect(t, err, NXDOMAIN)
}

func TestTimeoutExpiration(t *testing.T) {
	r := NewResolver(WithTimeout(10 * time.Millisecond))
	_, err := r.ResolveErr("1.com", "")
	st.Expect(t, err, ErrTimeout)
}

func TestDeadlineExceeded(t *testing.T) {
	r := NewResolver(WithTimeout(0))
	_, err := r.ResolveErr("1.com", "")
	st.Expect(t, err, context.DeadlineExceeded)
}

func TestResolveCtx(t *testing.T) {
	r := NewResolver()
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	_, err := r.ResolveCtx(ctx, "1.com", "")
	st.Expect(t, err, NXDOMAIN)
	cancel()
	_, err = r.ResolveCtx(ctx, "1.com", "")
	st.Expect(t, err, context.Canceled)
}

func TestResolveContext(t *testing.T) {
	r := NewResolver()
	ctx, cancel := context.WithCancel(context.Background())
	_, err := r.ResolveContext(ctx, "1.com", "")
	st.Expect(t, err, NXDOMAIN)
	cancel()
	_, err = r.ResolveContext(ctx, "1.com", "")
	st.Expect(t, err, context.Canceled)
}

func TestResolverCache(t *testing.T) {
	r := NewResolver()
	r.cache.capacity = 10
	r.cache.m.Lock()
	st.Expect(t, len(r.cache.entries), 0)
	r.cache.m.Unlock()
	for i := range 10 {
		r.Resolve(fmt.Sprintf("%d.com", i), "")
	}
	r.cache.m.Lock()
	st.Expect(t, len(r.cache.entries), 10)
	r.cache.m.Unlock()
	rrs, err := r.ResolveErr("a.com", "")
	st.Expect(t, err, NXDOMAIN)
	st.Expect(t, rrs, (RRs)(nil))
	r.cache.m.Lock()
	st.Expect(t, r.cache.entries["a.com"], entry(nil))
	st.Expect(t, len(r.cache.entries), 10)
	r.cache.m.Unlock()
}

func TestGoogleA(t *testing.T) {
	r := NewResolver()
	rrs, err := r.ResolveErr("google.com", "A")
	st.Expect(t, err, nil)
	st.Expect(t, len(rrs) >= 4, true)
	st.Expect(t, count(rrs, func(rr RR) bool { return rr.Type == "NS" }) >= 2, true)
	st.Expect(t, count(rrs, func(rr RR) bool { return rr.Type == "A" }) >= 1, true)
}

func TestGooglePTR(t *testing.T) {
	r := NewResolver()
	rrs, err := r.ResolveErr("99.17.217.172.in-addr.arpa", "PTR")
	st.Expect(t, err, nil)
	st.Expect(t, len(rrs) >= 2, true)
	st.Expect(t, count(rrs, func(rr RR) bool { return rr.Type == "PTR" }) >= 1, true)
}

func TestGoogleMX(t *testing.T) {
	r := NewResolver()
	rrs, err := r.ResolveErr("google.com", "MX")
	st.Expect(t, err, nil)
	st.Expect(t, len(rrs) >= 4, true)
	st.Expect(t, count(rrs, func(rr RR) bool { return rr.Type == "NS" }) >= 2, true)
	st.Expect(t, count(rrs, func(rr RR) bool { return rr.Type == "MX" }) >= 1, true)
}

func TestGoogleAny(t *testing.T) {
	time.Sleep(Timeout) // To address flaky test on GitHub Actions
	r := NewResolver()
	rrs, err := r.ResolveErr("google.com", "")
	st.Expect(t, err, nil)
	st.Expect(t, len(rrs) >= 1, true)
	st.Expect(t, count(rrs, func(rr RR) bool { return rr.Type == "NS" }) >= 2, true)
	st.Expect(t, count(rrs, func(rr RR) bool { return rr.Type == "A" }) >= 1, true)
}

func TestGoogleMulti(t *testing.T) {
	r := NewResolver()
	_, err := r.ResolveErr("google.com", "A")
	st.Expect(t, err, nil)
	rrs, err := r.ResolveErr("google.com", "TXT")
	st.Expect(t, err, nil)
	st.Expect(t, len(rrs) >= 1, true)
	// Google will have at least an SPF record, but might transiently have verification records too.
	st.Expect(t, count(rrs, func(rr RR) bool { return rr.Type == "TXT" }) >= 1, true)
	st.Expect(t, count(rrs, func(rr RR) bool { return rr.Type == "A" }), 0)
}

func TestGoogleTXT(t *testing.T) {
	checkTXT(t, "google.com")
}

func TestCloudflareTXT(t *testing.T) {
	checkTXT(t, "cloudflare.com")
}

func TestGoogleTXTTCPRetry(t *testing.T) {
	r := NewResolver()
	rrs, err := r.ResolveErr("google.com", "TXT")
	st.Expect(t, err, nil)
	st.Expect(t, len(rrs) >= 4, true)

	r2 := NewResolver(WithTCPRetry())
	rrs2, err := r2.ResolveErr("google.com", "TXT")
	st.Expect(t, err, nil)
	st.Expect(t, len(rrs2) > len(rrs), true)
}

func TestGithubCNAME(t *testing.T) {
	r := NewResolver()
	rrs, err := r.ResolveErr("www.github.com", "A")
	st.Expect(t, err, nil)
	st.Expect(t, len(rrs) >= 1, true)
	st.Expect(t, count(rrs, func(rr RR) bool { return rr.Type == "CNAME" }) >= 1, true) // resolved first
	st.Expect(t, count(rrs, func(rr RR) bool { return rr.Type == "A" }) >= 1, true)     // records for CNAME target
}

func TestAppleA(t *testing.T) {
	r := NewResolver()
	rrs, err := r.ResolveErr("apple.com", "A")
	st.Expect(t, err, nil)
	st.Expect(t, count(rrs, func(rr RR) bool { return rr.Type == "A" }) >= 1, true)
}

func TestHerokuTXT(t *testing.T) {
	r := NewResolver()
	rrs, err := r.ResolveErr("us-east-1-a.route.herokuapp.com", "TXT")
	st.Expect(t, err, nil)
	st.Expect(t, count(rrs, func(rr RR) bool { return rr.Type == "TXT" }), 0)
}

func TestHerokuMulti(t *testing.T) {
	r := NewResolver()
	_, err := r.ResolveErr("us-east-1-a.route.herokuapp.com", "A")
	st.Expect(t, err, nil)
	rrs, err := r.ResolveErr("us-east-1-a.route.herokuapp.com", "TXT")
	st.Expect(t, err, nil)
	st.Expect(t, count(rrs, func(rr RR) bool { return rr.Type == "TXT" }), 0)
	st.Expect(t, count(rrs, func(rr RR) bool { return rr.Type == "A" }), 0)
}

func TestBlueOvenA(t *testing.T) {
	t.Skip("DNS changed 2018-11, so disabling this.")
	r := NewResolver()
	rrs, err := r.ResolveErr("blueoven.com", "A")
	st.Expect(t, err, nil)
	st.Expect(t, len(rrs), 2)
	st.Expect(t, count(rrs, func(rr RR) bool { return rr.Type == "NS" && rr.Name == "blueoven.com." }), 2)
}

func TestBlueOvenAny(t *testing.T) {
	t.Skip("DNS changed 2018-11, so disabling this.")
	r := NewResolver()
	rrs, err := r.ResolveErr("blueoven.com", "")
	st.Expect(t, err, nil)
	st.Expect(t, len(rrs), 2)
	st.Expect(t, count(rrs, func(rr RR) bool { return rr.Type == "NS" && rr.Name == "blueoven.com." }), 2)
}

func TestBlueOvenMulti(t *testing.T) {
	t.Skip("DNS changed 2018-11, so disabling this.")
	r := NewResolver()
	_, err := r.ResolveErr("blueoven.com", "A")
	st.Expect(t, err, nil)
	_, err = r.ResolveErr("blueoven.com", "TXT")
	st.Expect(t, err, nil)
	rrs, err := r.ResolveErr("blueoven.com", "")
	st.Expect(t, err, nil)
	st.Expect(t, len(rrs), 2)
	st.Expect(t, all(rrs, func(rr RR) bool { return rr.Type == "NS" }), true)
}

func TestBazCoUKAny(t *testing.T) {
	time.Sleep(Timeout) // To address flaky test on GitHub Actions
	r := NewResolver()
	rrs, err := r.ResolveErr("baz.co.uk", "")
	st.Expect(t, err, nil)
	st.Expect(t, len(rrs) >= 2, true)
	st.Expect(t, count(rrs, func(rr RR) bool { return rr.Type == "NS" }) >= 2, true)
}

func TestTTL(t *testing.T) {
	r := NewExpiring(0)
	rrs, err := r.ResolveErr("google.com", "A")
	st.Expect(t, err, nil)
	st.Assert(t, len(rrs) >= 4, true)
	rr := rrs[0]
	st.Expect(t, rr.Expiry.IsZero(), false)
}

func checkTXT(t *testing.T, domain string) {
	r := NewResolver(WithTCPRetry())
	rrs, err := r.ResolveErr(domain, "TXT")
	st.Expect(t, err, nil)

	rrs2, err := net.LookupTXT(domain)
	st.Expect(t, err, nil)
	for _, rr := range rrs2 {
		exists := false
		for _, rr2 := range rrs {
			if rr2.Type == "TXT" && rr == rr2.Value {
				exists = true
			}
		}
		if !exists {
			t.Errorf("TXT record %q not found", rr)
		}
	}
	c := count(rrs, func(rr RR) bool { return rr.Type == "TXT" })
	if c != len(rrs2) {
		t.Errorf("TXT record count mismatch: %d != %d", c, len(rrs2))
	}
}

var testResolver *Resolver

func BenchmarkResolve(b *testing.B) {
	testResolver = NewResolver()
	for b.Loop() {
		testResolve()
	}
}

func BenchmarkResolveErr(b *testing.B) {
	testResolver = NewResolver()
	for b.Loop() {
		testResolveErr()
	}
}

func testResolve() {
	testResolver.Resolve("google.com", "")
	testResolver.Resolve("blueoven.com", "")
	testResolver.Resolve("baz.co.uk", "")
	testResolver.Resolve("us-east-1-a.route.herokuapp.com", "")
}

func testResolveErr() {
	testResolver.ResolveErr("google.com", "")
	testResolver.ResolveErr("blueoven.com", "")
	testResolver.ResolveErr("baz.co.uk", "")
	testResolver.ResolveErr("us-east-1-a.route.herokuapp.com", "")
}

// BenchmarkResolveOOB benchmarks resolution of domains with out-of-bailiwick nameservers.
func BenchmarkResolveOOB(b *testing.B) {
	testResolver = NewResolver()
	for b.Loop() {
		testResolver.ResolveErr("pnnl.gov", "A")
	}
}

func count(rrs RRs, f func(RR) bool) (out int) {
	for _, rr := range rrs {
		if f(rr) {
			out++
		}
	}
	return
}

func sum(rrs RRs, f func(RR) int) (out int) {
	for _, rr := range rrs {
		out += f(rr)
	}
	return
}

func all(rrs RRs, f func(RR) bool) (out bool) {
	for _, rr := range rrs {
		if !f(rr) {
			return false
		}
	}
	return true
}

// TestMultiLabelDelegationPTR tests resolution across multi-label delegations
// in reverse DNS, where a parent zone delegates several labels down
// (e.g. 8.in-addr.arpa delegates 8.8.8.in-addr.arpa directly, skipping 8.8.in-addr.arpa).
// See https://github.com/domainr/dnsr/issues/148
func TestMultiLabelDelegationPTR(t *testing.T) {
	r := NewResolver()
	rrs, err := r.ResolveErr("8.8.8.8.in-addr.arpa", "PTR")
	st.Expect(t, err, nil)
	st.Expect(t, len(rrs) >= 1, true)
	st.Expect(t, count(rrs, func(rr RR) bool { return rr.Type == "PTR" }) >= 1, true)
}

// TestOOB tests out-of-bailiwick (OOB) nameserver resolution.
// pnnl.gov uses nameservers in .net (adns1.es.net, adns2.es.net),
// which .gov nameservers cannot provide glue records for.
// See https://github.com/domainr/dnsr/issues/174
func TestOOB(t *testing.T) {
	r := NewResolver()
	rrs, err := r.ResolveErr("pnnl.gov", "A")
	st.Expect(t, err, nil)
	st.Expect(t, len(rrs) >= 3, true)
	st.Expect(t, count(rrs, func(rr RR) bool { return rr.Type == "NS" }) >= 2, true)
	st.Expect(t, count(rrs, func(rr RR) bool { return rr.Type == "A" }) >= 1, true)
}

// TestOOBOtherDomains tests other domains from issue #174.
func TestOOBOtherDomains(t *testing.T) {
	r := NewResolver()
	for _, domain := range []string{"lbl.gov", "nrel.gov"} {
		rrs, err := r.ResolveErr(domain, "A")
		if err != nil {
			t.Errorf("%s: %v", domain, err)
			continue
		}
		if len(rrs) == 0 {
			t.Errorf("%s: no records returned", domain)
		}
	}
}*/