package clients

import (
	"testing"
	"fmt"
	"context"
	"time"
	"strings"

	"github.com/mr-torgue/dnsr/pkg/clients"
	"github.com/miekg/dns"
)

func TestNewClientConfig(t *testing.T) {
	wantType := "*clients.DOQClient"
	config := clients.NewClientConfig(nil, "doq", 5)
	client, err := clients.LoadClient(config)
	gotType := fmt.Sprintf("%T", client)
	if err != nil {
		t.Errorf("Error creating client: %s\n", err)
	}
	if gotType != wantType {// Check the result
		t.Errorf("Client not initialized: got %s, expected %s\n", gotType, wantType)
	}	
	if config.ClientType != "doq" {
		t.Errorf("config.ClientType is incorrect: got %s, expected %s\n", config.ClientType, "doq")
	}
	if config.Timeout != 5 * time.Second {
		t.Errorf("config.Timeout is incorrect: got %d, expected %d\n", config.Timeout, 5 * time.Second)
	}
}


func TestLookup(t *testing.T) {
	tests := []struct {// Define a struct for each test case and create a slice of them
        name string
        qname string
        qtype string
		ns string // ns is in IP format (no port number)
		rd    bool // sets recursion
		rcode int
		expected string // uses string.contains, which is not optimal
    }{
        {"Client should return A record of google.com", "google.com", "A", "9.9.9.9", true, dns.RcodeSuccess, "142.251.222.14"},
        {"Client should return A record of testing.com", "testing.com", "A", "9.9.9.9", true, dns.RcodeSuccess, "104.26.5.28"},
        {"Client should return A record of testing.com by using the classic fallback", "testing.com", "A", "8.8.8.8", true, dns.RcodeSuccess, "104.26.5.28"},
    }
	config := clients.NewClientConfig(nil, "doq", 2)
	client, _ := clients.LoadClient(config)

    for _, tt := range tests {// Loop over each test case
        t.Run(tt.name, func(t *testing.T) {// Run each case as a subtest
			ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
			dst := clients.Destination{ Server: tt.ns}
			// create the question
			var qmsg dns.Msg
			qmsg.SetQuestion(tt.qname, clients.QtypeStr2Int(tt.qtype))
			qmsg.MsgHdr.RecursionDesired = tt.rd
			// create flags
			flags := clients.QueryFlags{ RD: tt.rd }

			msgs, err := client.Lookup(ctx, dst, qmsg.Question, flags)
			if err != nil {
				t.Errorf("err: %s\n", err)
			}
			for _, msg := range msgs {
				if msg == nil {
					t.Fatalf("msg should not be nil")
				}
				if msg.MsgHdr.Rcode != tt.rcode {
					t.Errorf("Expected rcode %d but got %d", tt.rcode, msg.MsgHdr.Rcode)
				}
				if tt.expected != "" && !strings.Contains(msg.String(), tt.expected) {
					t.Errorf("Expected message to contain %s but got %s", tt.expected, msg.String())
				}
			}
        })
    }
}
	