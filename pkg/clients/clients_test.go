package clients

import (
	"testing"
	//"reflect"
	"fmt"

	"github.com/mr-torgue/dnsr/pkg/clients"
)

// Tests if the proper 
func TestNewClientConfig(t *testing.T) {

    tests := []struct {// Define a struct for each test case and create a slice of them
        name string
        clientType string
        wantType string
    }{
        {"udp client", "udp", "clients.ClientConfig"},
        {"tcp client", "tcp", "clients.ClientConfig"},
        {"quic client", "quic", "clients.ClientConfig"},
    }

    for _, tt := range tests {// Loop over each test case
        t.Run(tt.name, func(t *testing.T) {// Run each case as a subtest
			config := clients.NewClientConfig(nil, tt.clientType, 0)
			gotType := fmt.Sprintf("%T", config)
            if gotType != tt.wantType {// Check the result
                t.Errorf("Config not initialized: got %s, expected %s\n", gotType, tt.wantType)
            }
			if config.ClientType != tt.clientType {
                t.Errorf("config.ClientType != tt.clientType: got %s, expected %s\n", config.ClientType, tt.clientType)
			}
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

    for _, tt := range tests {// Loop over each test case
        t.Run(tt.name, func(t *testing.T) {// Run each case as a subtest
			config := clients.NewClientConfig(nil, tt.clientType, 0)
			client, err := clients.LoadClient(config)
			gotType := fmt.Sprintf("%T", client)
			if tt.wantType != "" { // for positive tests
				if err != nil {
					t.Errorf("Error creating client: %s\n", err)
				}
				if gotType != tt.wantType {// Check the result
					t.Errorf("Client not initialized: got %s, expected %s\n", gotType, tt.wantType)
				}
			} else { // for negative tests
				if err == nil {
					t.Errorf("Non-existing client should have resulted in an error\n")
				}
			}
        })
    }
}