package clients

import (
	"context"
	"log/slog"
	"time"
	"fmt"

	"github.com/mr-torgue/dnsr/pkg/models"
	"github.com/mr-torgue/dnsr/pkg/utils"
	"github.com/miekg/dns"
)

// ClientConfig represent a set of common options to configure a Client.
type ClientConfig struct {
	logger             *slog.Logger
	clientType		   string
	timeout            time.Duration // in seconds
	searchList         []string
	ndots              int
	useIPv4            bool
	useIPv6            bool
	//Strategy           string
	insecureSkipVerify bool
	useTCPFallback 	   bool
	useUDPFallback     bool
}
	
// Default values
const (
	DefaultClientType = "udp"
	DefaultTimeout = 2 // in seconds
	DefaultNdots = 0
	DefaultIPv4 = false
	DefaultIPv6 = false
	DefaultInsecureSkipVerify = true
	DefaultUseTCPFallback = true
	DefaultUseUDPFallback = true
)

// ClientConfig options
type Option func(*ClientConfig)

// WithLogger specifies a logger
func WithLogger(logger *slog.Logger) Option {
	return func(config *ClientConfig) {
		config.logger = logger
	}
}

// WithDebugLogger creates a logger in debug mode
func WithDebugLogger() Option {
	return func(config *ClientConfig) {
		config.logger = utils.InitLogger(true)
	}
}


func WithClientType(clientType string) Option {
	return func(config *ClientConfig) {
		config.clientType = clientType
	}
}

func WithTimeout(timeout time.Duration) Option {
	return func(config *ClientConfig) {
		config.timeout = timeout * time.Second
	}
}

func WithUseIPv4(useIPv4 bool) Option {
	return func(config *ClientConfig) {
		config.useIPv4 = useIPv4
	}
}

func WithUseIPv6(useIPv6 bool) Option {
	return func(config *ClientConfig) {
		config.useIPv6 = useIPv6
	}
}

func WithInsecureSkipVerify(insecureSkipVerify bool) Option {
	return func(config *ClientConfig) {
		config.insecureSkipVerify = insecureSkipVerify
	}
}

func WithUseTCPFallback(useTCPFallback bool) Option {
	return func(config *ClientConfig) {
		config.useTCPFallback = useTCPFallback
	}
}

func WithUseUDPFallback(useUDPFallback bool) Option {
	return func(config *ClientConfig) {
		config.useUDPFallback = useUDPFallback
	}
}

// Destination specifies the endpoint
type Destination struct {
	Server 			   string // IP address
	TLSHostname        string 
}

// Client implements the configuration for a DNS Client. 
// In contrast to doggo, a Client does not specify the endpoint
type Client interface {
	query(ctx context.Context, dst Destination, question dns.Question, flags QueryFlags) (*dns.Msg, error)
	Lookup(ctx context.Context, dst Destination, questions []dns.Question, flags QueryFlags) ([]*dns.Msg, error)
}

// Returns a new ClientConfig
func NewClientConfig(options ...Option) (*ClientConfig) {
	// set default values
	config := &ClientConfig {
		clientType: DefaultClientType,
		timeout: DefaultTimeout * time.Second,
		searchList: []string{},
		ndots: DefaultNdots,
		useIPv4: DefaultIPv4,
		useIPv6: DefaultIPv6,
		insecureSkipVerify: DefaultInsecureSkipVerify,
		useTCPFallback: DefaultUseTCPFallback,
		useUDPFallback: DefaultUseUDPFallback,
	}
	// parse options
	for _, o := range options {
		o(config)
	}
	// create new logger if none provided 
	if config.logger == nil {
		config.logger = utils.InitLogger(false)
	}
	return config
}

// String returns a string representation of the ClientConfig
func (c *ClientConfig) String() string {
	return fmt.Sprintf("ClientConfig{logger: %v, clientType: %s, useIPv4: %t, useIPv6: %t, searchList: %v, ndots: %d, timeout: %v, insecureSkipVerify: %t, useTCPFallback: %t, useUDPFallback: %t}",
		c.logger, c.clientType, c.useIPv4, c.useIPv6, c.searchList, c.ndots, c.timeout, c.insecureSkipVerify, c.useTCPFallback, c.useUDPFallback)
}

// LoadClient loads the correct Client based on the configuration.
func LoadClient(config *ClientConfig) (Client, error) {
	var (
		client Client
		err error
	)
	switch(config.clientType) {
	case models.DOHClient:
		config.logger.Debug("initiating DOH client")
		client, err = NewDOHClient(config)
	case models.DOTClient:
		config.logger.Debug("initiating DOT client")
		client, err = NewClassicClient(config, ClassicClientOpts{ UseTLS: true, UseTCP: true })
	case models.TCPClient:
		config.logger.Debug("initiating TCP client")
		client, err = NewClassicClient(config, ClassicClientOpts{ UseTLS: false, UseTCP: true })
	case models.UDPClient:
		config.logger.Debug("initiating UDP client")
		client, err = NewClassicClient(config, ClassicClientOpts{ UseTLS: false, UseTCP: false })
	case models.DNSCryptClient:
		config.logger.Debug("initiating DNSCrypt client")
		client, err = NewDNSCryptClient(config, DNSCryptClientOpts{ UseTCP: false })
	case models.DOQClient:
		config.logger.Debug("initiating DOQ client")
		client, err = NewDOQClient(config)
	default:
		return nil, fmt.Errorf("Please use a valid client!")
	}
	if err != nil {
		return nil, fmt.Errorf("Could not create client!")
	}
	config.logger.Debug(fmt.Sprintf("Using the following configuration: %s", config.String()))
	return client, nil
}