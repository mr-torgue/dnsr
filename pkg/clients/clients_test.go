package clients

import (
	"testing"
    "time"
	"fmt"
	"context"

	"github.com/miekg/dns"
  	"github.com/stretchr/testify/assert"
	"github.com/go-openapi/testify/require"
)

// Tests if the proper 
func TestNewClientConfig(t *testing.T) {

    // test default values
    config := NewClientConfig()
    gotType := fmt.Sprintf("%T", config)
    assert.NotNil(t, config.logger, "Logger should not be nil")
    assert.Equal(t, "*clients.ClientConfig", gotType, "Types should match")
    assert.Equal(t, DefaultClientType, config.clientType, "Type string should match")
    assert.Equal(t, DefaultTimeout * time.Second, config.timeout, "Timeout should match")
    assert.Equal(t, DefaultIPv4, config.useIPv4, "useIPv4 should match")
    assert.Equal(t, DefaultIPv6, config.useIPv6, "useIPv6 should match")
    assert.Equal(t, DefaultInsecureSkipVerify, config.insecureSkipVerify, "insecureSkipVerify should match")
    assert.Equal(t, DefaultUseTCPFallback, config.useTCPFallback, "useTCPFallback should match")
    assert.Equal(t, DefaultUseUDPFallback, config.useUDPFallback, "useUDPFallback string should match")

    tests := []struct {// Define a struct for each test case and create a slice of them
        name string
        clientType string
        timeout time.Duration
        ipv4 bool
        ipv6 bool
        insecureSkipVerify bool
        useTCPFallback bool
        useUDPFallback bool
        wantType string
    }{
        {"udp client", "udp", 0, true, true, true, true, true, "*clients.ClientConfig"},
        {"tcp client", "tcp", 0, true, true, true, true, true, "*clients.ClientConfig"},
        {"quic client", "quic", 0, true, true, true, true, true, "*clients.ClientConfig"},
        {"doh client", "doh", 0, true, true, true, true, true, "*clients.ClientConfig"},
        {"doh client", "no real client", 230, false, false, false, false, false, "*clients.ClientConfig"},
        {"doh client", "no real client", 44444, false, true, false, false, false, "*clients.ClientConfig"},
    }
    

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {

			config = NewClientConfig(
                WithClientType(tt.clientType), 
                WithTimeout(tt.timeout), 
                WithUseIPv4(tt.ipv4),
                WithUseIPv6(tt.ipv6),
                WithInsecureSkipVerify(tt.insecureSkipVerify),
                WithUseTCPFallback(tt.useTCPFallback),
                WithUseUDPFallback(tt.useUDPFallback),
            )

			gotType := fmt.Sprintf("%T", config)
            assert.NotNil(t, config.logger, "Logger should not be nil")
  			assert.Equal(t, tt.wantType, gotType, "Types should match")
  			assert.Equal(t, tt.clientType, config.clientType, "Type string should match")
  			assert.Equal(t, tt.timeout * time.Second, config.timeout, "Timeout should match")
  			assert.Equal(t, tt.ipv4, config.useIPv4, "useIPv4 should match")
  			assert.Equal(t, tt.ipv6, config.useIPv6, "useIPv6 should match")
  			assert.Equal(t, tt.insecureSkipVerify, config.insecureSkipVerify, "insecureSkipVerify should match")
  			assert.Equal(t, tt.useTCPFallback, config.useTCPFallback, "useTCPFallback should match")
  			assert.Equal(t, tt.useUDPFallback, config.useUDPFallback, "useUDPFallback string should match")
        })
    }
}

// Tets if LoadClient returns the proper client
func TestLoadClient(t *testing.T) {
    tests := []struct {// Define a struct for each test case and create a slice of them
        name string
        clientType string
        wantType string
    }{
        {"udp client", "udp", "*clients.ClassicClient"},
        {"tcp client", "tcp", "*clients.ClassicClient"},
        {"quic client", "doq", "*clients.DOQClient"},
        {"doh client", "doh", "*clients.DOHClient"},
        {"dot client", "dot", "*clients.ClassicClient"},
        {"dnscrypt client", "dnscrypt", "*clients.DNSCryptClient"},
        {"non-existing client", "non-existing", ""},
        {"non-existing client 2", "Udp", ""},
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
			config := NewClientConfig(WithClientType(tt.clientType), WithTimeout(0))
			client, err := LoadClient(config)
			gotType := fmt.Sprintf("%T", client)
            assert.Equal(t, time.Duration(0), config.timeout, "Timeout should match")
			if tt.wantType != "" { // for positive tests
                assert.Nil(t, err, "Client should not be nil")
                assert.Equal(t, tt.wantType, gotType, "Types should match")
			} else { // for negative tests
                assert.NotNil(t, err, "Client should be nil")
			}
        })
    }
}

func TestLookupClassic(t *testing.T) {

	type TestCase struct {
		name     string
		qname    string
		qtype    string
		ns       string // ns is in IP format (no port number)
		tlsHostname string // in case of TLS or QUIC
		rd       bool   // sets recursion
		rcode    int
		timeout  time.Duration
		expected string // uses string.contains, which is not optimal
		expectedError string
	}

	type TestCaseConfig struct {
		name     string        
		clientType string
        timeout time.Duration
        ipv4 bool
        ipv6 bool
        insecureSkipVerify bool
        useTCPFallback bool
        useUDPFallback bool
		testCases []TestCase
	}


	tests := []TestCaseConfig {
		{
			name: "UDP client with 10 second timeout and no TCP fallback",
			clientType: "udp",
			timeout: 1,
			ipv4: false,
			ipv6: false,
			insecureSkipVerify: false,
			useTCPFallback: false,
			useUDPFallback: false,			
			testCases: []TestCase {
				{"[UDP] Client should return A record of folmer.info", "folmer.info", "A", "8.8.8.8", "dns.google", true, dns.RcodeSuccess, 10, "65.109.0.142", ""},
				{"[UDP] Use different resolver", "folmer.info", "A", "9.9.9.9", "dns.quad9.net", true, dns.RcodeSuccess, 10, "65.109.0.142", ""},
				{"[UDP] Use different RR (TXT)", "folmer.info", "TXT", "9.9.9.9", "dns.quad9.net", true, dns.RcodeSuccess, 10, "protonmail-verification=9fcd905c800df450c63a61d5585f0ad3439bc0f5", ""},
				{"[UDP] Set RD to false with public resolver", "folmer.info", "TXT", "8.8.8.8", "dns.google", false, dns.RcodeServerFailure, 10, "", ""}, // don't know why ServFail
				{"[UDP] Set RD to false with root server", "folmer.info", "TXT", "198.41.0.4", "a.root-servers.net", false, dns.RcodeSuccess, 10, "a0.info.afilias-nst.info.", ""},
				// use different domain
				{"[UDP] Client should return NXDomain", "a.com", "A", "8.8.8.8", "dns.google", true, dns.RcodeNameError, 10, "", ""},
				{"[UDP] Client should not use TCP fallback", "cisco.com", "TXT", "8.8.8.8", "dns.google", true, dns.RcodeSuccess, 10, "", "truncated response and TCP retransmission disabled"},
				{"[UDP] Client should timeout", "folmer.info", "A", "8.8.8.8", "dns.google", true, dns.RcodeSuccess, 0, "65.109.0.142", "context deadline exceeded"},
			},
		},
		{
			name: "UDP client with 0 second timeout",
			clientType: "udp",
			timeout: 0,
			ipv4: false,
			ipv6: false,
			insecureSkipVerify: false,
			useTCPFallback: false,
			useUDPFallback: false,			
			testCases: []TestCase {
				{"[UDP] Client should timeout (global)", "folmer.info", "A", "8.8.8.8", "dns.google", true, dns.RcodeSuccess, 1, "65.109.0.142", "dial udp 8.8.8.8:53: i/o timeout"},
			},
		},
		{
			name: "UDP client with 10 second timeout and TCP fallback",
			clientType: "udp",
			timeout: 10,
			ipv4: false,
			ipv6: false,
			insecureSkipVerify: false,
			useTCPFallback: true,
			useUDPFallback: false,			
			testCases: []TestCase {
				{"[UDP] Client should return A record of folmer.info", "folmer.info", "A", "8.8.8.8", "dns.google", true, dns.RcodeSuccess, 2, "65.109.0.142", ""},
				{"[UDP] Client should use TCP fallback", "cisco.com", "TXT", "8.8.8.8", "dns.google", true, dns.RcodeSuccess, 10, "airtable-verification=d95d028f039252314cb7507fb88e4317", ""},
			},
		},	
		{
			name: "TCP client with 10 second timeout and no TCP fallback",
			clientType: "tcp",
			timeout: 10,
			ipv4: false,
			ipv6: false,
			insecureSkipVerify: false,
			useTCPFallback: false,
			useUDPFallback: false,			
			testCases: []TestCase {
				{"Client should return A record of folmer.info", "folmer.info", "A", "8.8.8.8", "dns.google", true, dns.RcodeSuccess, 2, "65.109.0.142", ""},
			},
		},
		{
			name: "TLS client with 10 second timeout, no TCP fallback and TLS verification",
			clientType: "dot",
			timeout: 10,
			ipv4: false,
			ipv6: false,
			insecureSkipVerify: false,
			useTCPFallback: true,
			useUDPFallback: false,			
			testCases: []TestCase {
				{"[TLS] Client should return A record of folmer.info", "folmer.info", "A", "8.8.8.8", "dns.google", true, dns.RcodeSuccess, 2, "65.109.0.142", ""},
				{"[TLS] Client should return A record of folmer.info", "folmer.info", "A", "8.8.8.8", "npropertls", true, dns.RcodeSuccess, 2, "65.109.0.142", "tls: failed to verify certificate:"},
			},
		},
		{
			name: "TLS client with 10 second timeout",
			clientType: "dot",
			timeout: 10,
			ipv4: false,
			ipv6: false,
			insecureSkipVerify: true,
			useTCPFallback: true,
			useUDPFallback: false,			
			testCases: []TestCase {
				{"[TLS] Client should return A record of folmer.info", "folmer.info", "A", "8.8.8.8", "dns.google", true, dns.RcodeSuccess, 2, "65.109.0.142", ""},
				{"[TLS] Client should return A record of folmer.info", "folmer.info", "A", "8.8.8.8", "npropertls", true, dns.RcodeSuccess, 2, "65.109.0.142", ""},
			},
		},
		{
			name: "DoQ client with 1 second timeout",
			clientType: "doq",
			timeout: 1,
			ipv4: false,
			ipv6: false,
			insecureSkipVerify: false,
			useTCPFallback: false,
			useUDPFallback: false,			
			testCases: []TestCase {
				{"[QUIC] Client should timeout", "folmer.info", "A", "8.8.8.8", "dns.google", true, dns.RcodeSuccess, 10, "65.109.0.142", "context deadline exceeded"},
                // test fallback
			},
		},
		{
			name: "DoH client with 1 second timeout",
			clientType: "doh",
			timeout: 1,
			ipv4: false,
			ipv6: false,
			insecureSkipVerify: false,
			useTCPFallback: false,
			useUDPFallback: false,			
			testCases: []TestCase {
				{"[DoH] Client no supported by resolver", "folmer.info", "A", "8.8.8.8", "dns.google", true, dns.RcodeSuccess, 10, "65.109.0.142", "unpack error. Server does not support DoH."},
				{"[DoH] Client should timeout", "folmer.info", "A", "217.169.20.23", "dns.aa.net.uk", true, dns.RcodeSuccess, 10, "65.109.0.142", "context deadline exceeded"}, 
				{"[DoH] Client should resolve folmer.info", "folmer.info", "A", "45.90.30.0", "anycast.dns.nextdns.io", true, dns.RcodeSuccess, 10, "65.109.0.142", ""},
                // test fallback
			},
		},
		{
			name: "dnscrypt client with 1 second timeout",
			clientType: "dnscrypt",
			timeout: 1,
			ipv4: false,
			ipv6: false,
			insecureSkipVerify: false,
			useTCPFallback: false,
			useUDPFallback: false,			
			testCases: []TestCase {
				{"[dnscrypt] Client no supported by resolver", "folmer.info", "A", "AQMAAAAAAAAAETk0LjE0MC4xNC4xNDo1NDQzINErR_JS3PLCu_iZEIbq95zkSV2LFsigxDIuUso_OQhzIjIuZG5zY3J5cHQuZGVmYXVsdC5uczEuYWRndWFyZC5jb20", "94.140.14.14", true, dns.RcodeSuccess, 10, "65.109.0.142", ""},
                // test fallback
			},
		},
		/*
		{
			name: "DoQ client with 1 second timeout and no fallback",
			clientType: "doq",
			timeout: 1,
			ipv4: false,
			ipv6: false,
			insecureSkipVerify: false,
			useTCPFallback: false,
			useUDPFallback: false,			
			testCases: []TestCase {
				{"[QUIC] Client should timeout", "folmer.info", "A", "8.8.8.8", "dns.google", true, dns.RcodeSuccess, 10, "65.109.0.142", context.DeadlineExceeded},
			},
		},*/
	}

	/*
	tests := TestCaseConfig {
        name string
        qname string
        qtype string
		ns string // ns is in IP format (no port number)
		rd    bool // sets recursion
		rcode int
		expected string // uses string.contains, which is not optimal
    }{
		{

		}
        {"Client should return A record of google.com", "google.com", "A", "8.8.8.8", true, dns.RcodeSuccess, 2, "142.250.207.14"},
        {"Client should return A record of testing.com", "testing.com", "A", "8.8.8.8", true, dns.RcodeSuccess, 2, "104.26.5.28"},
        {"Client should return .com auth name servers", "testing.com", "A", "198.41.0.4", false, dns.RcodeSuccess, 2, "a.gtld-servers.net."},
        {"Client should timeout", "testing.com", "A", "9.9.9.9", true, dns.RcodeSuccess, 0, ""},
        {"Client should use TCP fallback", "cisco.com", "TXT", "9.9.9.9", true, dns.RcodeSuccess, 4, "intercom-domain-validation=8806e2f9-7626-4d9e-ae4d-2d655028629a"},
        {"Client should not use TCP fallback", "cisco.com", "TXT", "9.9.9.9", true, dns.RcodeSuccess, 4, ""},
    }
	*/
	var (
		config *ClientConfig
		client Client
		err error
	)

	// loop over client configurations
    for _, ttconfig := range tests {
		config = NewClientConfig(
			WithClientType(ttconfig.clientType), 
			WithTimeout(ttconfig.timeout), 
			WithUseIPv4(ttconfig.ipv4),
			WithUseIPv6(ttconfig.ipv6),
			WithInsecureSkipVerify(ttconfig.insecureSkipVerify),
			WithUseTCPFallback(ttconfig.useTCPFallback),
			WithUseUDPFallback(ttconfig.useUDPFallback),
			WithDebugLogger(),
		)
		
		// test config just to be sure
		gotType := fmt.Sprintf("%T", config)
		assert.NotNil(t, config.logger, "Logger should not be nil")
		assert.Equal(t, "*clients.ClientConfig", gotType, "Types should match")
		assert.Equal(t, ttconfig.clientType, config.clientType, "Type string should match")
		assert.Equal(t, ttconfig.timeout * time.Second, config.timeout, "Timeout should match")
		assert.Equal(t, ttconfig.ipv4, config.useIPv4, "useIPv4 should match")
		assert.Equal(t, ttconfig.ipv6, config.useIPv6, "useIPv6 should match")
		assert.Equal(t, ttconfig.insecureSkipVerify, config.insecureSkipVerify, "insecureSkipVerify should match")
		assert.Equal(t, ttconfig.useTCPFallback, config.useTCPFallback, "useTCPFallback should match")
		assert.Equal(t, ttconfig.useUDPFallback, config.useUDPFallback, "useUDPFallback string should match")

		// create and test client
		client, err = LoadClient(config)
        require.NotNil(t, client, "Client should not be nil")
        require.Nil(t, err, "Err should be nil")
		
		// sometimes the lookup changes the client type (fallbacks/retransmission). This shoudl not happen...
		clientType := fmt.Sprintf("%T", client)
		var (
			classic *ClassicClient
			oldClientNet string
		)
		if clientType == "*clients.ClassicClient" {
			classic = client.(*ClassicClient)
			oldClientNet = classic.client.Net
		}

		for _, tt := range ttconfig.testCases {
			t.Run(tt.name, func(t *testing.T) {
				ctx, _ := context.WithTimeout(context.Background(), tt.timeout * time.Second)
				dst := Destination{ Server: tt.ns, TLSHostname: tt.tlsHostname}
				// create the question
				var qmsg dns.Msg
				qmsg.SetQuestion(tt.qname, dns.StringToType[tt.qtype])
				qmsg.MsgHdr.RecursionDesired = tt.rd
				// create flags
				flags := QueryFlags{ RD: tt.rd }

				msgs, err := client.Lookup(ctx, dst, qmsg.Question, flags)
				if tt.expectedError != "" {
					assert.NotNil(t, err, "expected an error")
					assert.ErrorContains(t, err, tt.expectedError, "lookup errors should match")
				} else {
					assert.Greater(t, len(msgs), 0, "there should be at least 1 answer message")
					for _, msg := range msgs {
						fmt.Printf("msg: %s\n", msg.String())
						require.NotNil(t, msg, "msg should not be nil")
						assert.Equal(t, tt.rcode, msg.Rcode, "rcodes should match")
						assert.Contains(t, msg.String(), tt.expected, "answers should match")
					}
				}
				
				// check if client names are still the same
				if classic != nil {
					assert.Equal(t, oldClientNet, classic.client.Net, "client type should not change")
				}
			})
		}
    }
}
	