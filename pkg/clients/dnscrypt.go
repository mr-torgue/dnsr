package clients

import (
	"context"
	"fmt"

	"github.com/mr-torgue/dnsr/pkg/models"
	"github.com/ameshkov/dnscrypt/v2"
	"github.com/miekg/dns"
)

// DNSCryptClient represents the config options for setting up a Client.
type DNSCryptClient struct {
	client          *dnscrypt.Client
	config   		*ClientConfig
	opts			DNSCryptClientOpts
	fallbackClient  Client
}

// DNSCryptClientOpts holds options for setting up a DNSCrypt client.
type DNSCryptClientOpts struct {
	UseTCP bool
}

// NewDNSCryptClient accepts a list of nameservers and configures a DNS client.
func NewDNSCryptClient(config *ClientConfig, opts DNSCryptClientOpts) (Client, error) {
	net := "udp"
	if opts.UseTCP {
		net = "tcp"
	}

	client := &dnscrypt.Client{Net: net, Timeout: config.timeout, UDPSize: 4096}

	// create a fallback client
	var classicClient Client 
	var err error
	if config.useUDPFallback {
		classicClientConfig := config
		classicClientConfig.clientType = models.UDPClient
		classicClient, err = NewClassicClient(classicClientConfig, ClassicClientOpts{ UseTLS: false, UseTCP: false })
		if err != nil {
			config.logger.Info("Could not initialize fallback client in DNSCrypt!\n")
		}
	}

	return &DNSCryptClient{
		client:         client,
		config: 		config,
		opts: 			opts,
		fallbackClient: classicClient,
	}, nil
}

// Lookup implements the Client interface
func (c *DNSCryptClient) Lookup(ctx context.Context, dst Destination, questions []dns.Question, flags QueryFlags) ([]*dns.Msg, error) {
	return ConcurrentLookup(ctx, dst, questions, flags, c.query, c.config.logger)
}

// query performs a single DNS query
func (c *DNSCryptClient) query(ctx context.Context, dst Destination, question dns.Question, flags QueryFlags) (*dns.Msg, error) {
	var (
		in      *dns.Msg
		messages = prepareMessages(question, flags, c.config.ndots, c.config.searchList)
	)

	addr := "sdns://" + dst.Server
	clientInfo, err := c.client.Dial(addr)
	if err != nil {
		// fallback if enabled
		if c.config.useUDPFallback {
			c.config.logger.Debug("Cannot reach using dnscrypt, falling back to UDP!")
			return c.fallbackClient.query(ctx, dst, question, flags)
		}
		c.config.logger.Debug(fmt.Sprintf("Cannot reach using dnscrypt and no fallback enabled! Error: %s", err))
		return nil, err
	}

	for _, msg := range messages {
		c.config.logger.Debug("Attempting to resolve",
			"domain", msg.Question[0].Name,
			"ndots", c.config.ndots,
			"nameserver", addr,
		)

		//now := time.Now()

		// Use a channel to handle the result of the Exchange
		resultChan := make(chan struct {
			resp *dns.Msg
			err  error
		})

		go func() {
			resp, err := c.client.Exchange(&msg, clientInfo)
			resultChan <- struct {
				resp *dns.Msg
				err  error
			}{resp, err}
		}()

		// Wait for either the query to complete or the context to be cancelled
		select {
		case result := <-resultChan:
			if result.err != nil {
				return in, result.err
			}
			in = result.resp
			//rtt := time.Since(now)

			if in.Rcode == dns.RcodeSuccess {
				// stop iterating the searchlist.
				return in, nil
			}
		case <-ctx.Done():
			return in, ctx.Err()
		}
	}
	return in, nil
}
