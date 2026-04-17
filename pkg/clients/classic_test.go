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
	wantType := "*clients.ClassicClient"
	config := clients.NewClientConfig(nil, "udp", 5)
	client, err := clients.LoadClient(config)
	gotType := fmt.Sprintf("%T", client)
	if err != nil {
		t.Errorf("Error creating client: %s\n", err)
	}
	if gotType != wantType {// Check the result
		t.Errorf("Client not initialized: got %s, expected %s\n", gotType, wantType)
	}	
	// check opts
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
        {"google.com A", "google.com", "A", "8.8.8.8", true, dns.RcodeSuccess, "142.250.207.14"},
        {"testing.com A", "testing.com", "A", "8.8.8.8", true, dns.RcodeSuccess, "104.26.5.28"},
        {"testing.com A 2", "testing.com", "A", "198.41.0.4", false, dns.RcodeServerFailure, ""},
    }
	config := clients.NewClientConfig(nil, "udp", 5*time.Second)
	client, _ := clients.LoadClient(config)

    for _, tt := range tests {// Loop over each test case
        t.Run(tt.name, func(t *testing.T) {// Run each case as a subtest
			ctx, _ := context.WithTimeout(context.Background(), 2*time.Second)
			dst := clients.Destination{ Server: tt.ns}
			// create the question
			var qmsg dns.Msg
			qmsg.SetQuestion(tt.qname, clients.QtypeStr2Int(tt.qtype))
			qmsg.MsgHdr.RecursionDesired = tt.rd
			// create flags
			flags := clients.QueryFlags{ RD: tt.rd }

			fmt.Printf("QUERY:\n %s\n", qmsg.String())
			fmt.Printf("QUESTIONS:\n %+v\n", qmsg.Question)
			fmt.Printf("flags: %+v\n", flags)
			fmt.Printf("client: %+v\n", client)
			msgs, err := client.Lookup(ctx, dst, qmsg.Question, flags)
			fmt.Printf("Found %d messages\n", len(msgs))
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
				fmt.Printf("%s\n", msg.String())
			}
        })
    }
}
	