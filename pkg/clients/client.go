package clients

import (
	"context"
	"log/slog"
	"time"
	"pkg/models"

	"github.com/miekg/dns"
)

// ClientOptions represent a set of common options to configure a Client.
type ClientOptions struct {
	Logger *slog.Logger

	UseIPv4            bool
	UseIPv6            bool
	SearchList         []string
	Ndots              int
	Timeout            time.Duration
	Strategy           string
	InsecureSkipVerify bool
	useTCPFallback bool
	useUDPFallback bool

	// following values will get overwritten when using loadClient
	UseTLS 			   bool
	UseTCP 			   bool
	port 			   int
	clientType		   string
}

// Destination specifies the endpoint
type Destination struct {
	server 			   string // IP address
	TLSHostname        string 
}

// Client implements the configuration for a DNS Client. 
// In contrast to doggo, a Client does not specify the endpoint
type Client interface {
	Create(clientOpts Options)
	Lookup(ctx context.Context, destdstination Destination, questions []dns.Question, flags QueryFlags) ([]*dns.Msg, error)
}


// LoadClient loads the correct Client based on the configuration.
func LoadClient(clientType string, opts Options) (Client, error) {
	opts.clientType = clientType
	var client = nil
	var err = nil
	switch(clientType) {
	case models.DOHResolver:
		opts.Logger.Debug("initiating DOH resolver")
		opts.port = models.DefaultDOHPort
		client, err := NewDOHResolver(opts)
	case models.DOTResolver:
		opts.Logger.Debug("initiating DOT resolver")
		opts.UseTLS = true
		opts.UseTCP = true
		opts.port = models.DefaultTLSPort
		client, err := NewClassicResolver(opts)
	case models.TCPResolver:
		opts.Logger.Debug("initiating TCP resolver")
		opts.UseTLS = false
		opts.UseTCP = true
		opts.port = models.DefaultTCPPort
		client, err := NewClassicResolver(opts)
	case models.UDPResolver:
		opts.Logger.Debug("initiating UDP resolver")
		opts.UseTLS = false
		opts.UseTCP = false
		opts.port = models.DefaultUDPPort
		client, err := NewClassicResolver(opts)
	case models.DNSCryptResolver:
		opts.Logger.Debug("initiating DNSCrypt resolver")
		client, err := NewDNSCryptResolver(opts)
	case models.DOQResolver:
		opts.Logger.Debug("initiating DOQ resolver")
		opts.port = models.DefaultDOQPort
		client, err := NewDOQResolver(opts)
	}
	opts.Logger.Debug("Using the following configuration: %s\n", opts)
	return client, err
}
