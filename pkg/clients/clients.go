package clients

import (
	"context"
	"log/slog"
	"time"
	"fmt"

	"github.com/mr-torgue/dnsr/pkg/models"
	"github.com/miekg/dns"
)

// ClientConfig represent a set of common options to configure a Client.
type ClientConfig struct {
	Logger             *slog.Logger
	clientType		   string
	UseIPv4            bool
	UseIPv6            bool
	SearchList         []string
	Ndots              int
	Timeout            time.Duration
	Strategy           string
	InsecureSkipVerify bool
	useTCPFallback 	   bool
	useUDPFallback     bool

}

// Destination specifies the endpoint
type Destination struct {
	server 			   string // IP address
	TLSHostname        string 
}

// Client implements the configuration for a DNS Client. 
// In contrast to doggo, a Client does not specify the endpoint
type Client interface {
	Lookup(ctx context.Context, dst Destination, questions []dns.Question, flags QueryFlags) ([]*dns.Msg, error)
}

// Returns a new ClientConfig
func NewClientConfig(logger *slog.Logger, clientType string, timeout time.Duration) (ClientConfig) {
	return ClientConfig{
		Logger: 			logger,
		clientType: 		clientType,
		UseIPv4: 			false,
		UseIPv6: 			false,
		SearchList: 		[]string{""},
		Ndots: 				0,
		Timeout: 			timeout,
		Strategy: 			"",
		InsecureSkipVerify: true,
		useTCPFallback: 	true,
		useUDPFallback: 	true,
	}
}

// LoadClient loads the correct Client based on the configuration.
func LoadClient(config ClientConfig) (Client, error) {
	var (
		client Client
		err error
	)
	switch(config.clientType) {
	case models.DOHClient:
		config.Logger.Debug("initiating DOH client")
		client, err = NewDOHClient(config)
	case models.DOTClient:
		config.Logger.Debug("initiating DOT client")
		client, err = NewClassicClient(config, ClassicClientOpts{ UseTLS: true, UseTCP: true })
	case models.TCPClient:
		config.Logger.Debug("initiating TCP client")
		client, err = NewClassicClient(config, ClassicClientOpts{ UseTLS: false, UseTCP: true })
	case models.UDPClient:
		config.Logger.Debug("initiating UDP client")
		client, err = NewClassicClient(config, ClassicClientOpts{ UseTLS: false, UseTCP: false })
	case models.DNSCryptClient:
		config.Logger.Debug("initiating DNSCrypt client")
		client, err = NewDNSCryptClient(config, DNSCryptClientOpts{ UseTCP: false })
	case models.DOQClient:
		config.Logger.Debug("initiating DOQ client")
		client, err = NewDOQClient(config)
	default:
		return nil, fmt.Errorf("Please use a valid client!")
	}
	if err != nil {
		return nil, fmt.Errorf("Could not create client!")
	}
	config.Logger.Debugf("Using the following configuration: %s\n", config)
	return client, nil
}