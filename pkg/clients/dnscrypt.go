package clients

import (
	"context"
	"time"

	"github.com/ameshkov/dnscrypt/v2"
	"github.com/miekg/dns"
)

// DNSCryptClient represents the config options for setting up a Client.
type DNSCryptClient struct {
	client          *dnscrypt.Client
	clientOptions Options
	fallbackClient  ClassicClient
}


// NewDNSCryptClient accepts a list of nameservers and configures a DNS client.
func NewDNSCryptClient(clientOpts Options) (Client, error) {
	net := "udp"
	if clientOpts.UseTCP {
		net = "tcp"
	}

	client := &dnscrypt.Client{Net: net, Timeout: clientOpts.Timeout, UDPSize: 4096}

	var classicClient = nil
	if clientOpts.useUDPFallback {
		classicClientOpts := copyOpts(clientOpts)
		classicClientOpts.UseTLS = false
		classicClientOpts.UseTCP = false
		classicClientOpts.port = standard
		classicClient, err := NewClassicClient(classicClientOpts)
	}

	return &DNSCryptClient{
		client:          client,
		clientOptions: clientOpts,
		fallbackClient: classicClient,
	}, nil
}

// Lookup implements the Client interface
func (r *DNSCryptClient) Lookup(ctx context.Context, dst Destination, questions []dns.Question, flags QueryFlags) ([]*dns.Msg, error) {
	return ConcurrentLookup(ctx, questions, flags, r.query, r.clientOptions.Logger)
}

// query performs a single DNS query
func (r *DNSCryptClient) query(ctx context.Context, dst Destination, question dns.Question, flags QueryFlags) (*dns.Msg, error) {
	var messages = prepareMessages(question, flags, r.clientOptions.Ndots, r.clientOptions.SearchList)


	clientInfo, err := client.Dial(dst.server)
	if err != nil {
		// fallback if enabled
		if r.clientOptions.useUDPFallback && r.fallbackClient != nil {
			return fallbackClient.query(ctx, dst, question, flags)
		}
		return nil, err
	}

	for _, msg := range messages {
		r.clientOptions.Logger.Debug("Attempting to resolve",
			"domain", msg.Question[0].Name,
			"ndots", r.clientOptions.Ndots,
			"nameserver", dst.server,
		)

		now := time.Now()

		// Use a channel to handle the result of the Exchange
		resultChan := make(chan struct {
			resp *dns.Msg
			err  error
		})

		go func() {
			resp, err := r.client.Exchange(&msg, clientInfo)
			resultChan <- struct {
				resp *dns.Msg
				err  error
			}{resp, err}
		}()

		// Wait for either the query to complete or the context to be cancelled
		select {
		case result := <-resultChan:
			if result.err != nil {
				return rsp, result.err
			}
			in := result.resp
			rtt := time.Since(now)

			if len(output.Answers) > 0 || in.Rcode == dns.RcodeSuccess {
				// stop iterating the searchlist.
				return in, nil
			}
		case <-ctx.Done():
			return in, ctx.Err()
		}
	}
	return in, nil
}
