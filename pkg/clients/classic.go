package clients

import (
	"context"
	"crypto/tls"
	"time"

	"github.com/miekg/dns"
)

// ClassicClient represents the config options for setting up a Client.
type ClassicClient struct {
	client          *dns.Client
	clientOptions   Options
}

// NewClassicClient accepts a list of nameservers and configures a DNS client.
func NewClassicClient(clientOpts Options) (Client, error) {
	net := "udp"
	client := &dns.Client{
		Timeout: clientOpts.Timeout,
		Net:     "udp",
	}

	if clientOpts.UseTCP {
		net = "tcp"
	}

	if clientOpts.UseIPv4 {
		net = net + "4"
	}
	else if clientOpts.UseIPv6 {
		net = net + "6"
	}

	client.Net = net

	return &ClassicClient{
		client:          client,
		clientOptions: clientOpts,
	}, nil
}

// Lookup implements the Client interface
func (r *ClassicClient) Lookup(ctx context.Context, dst Destination, questions []dns.Question, flags QueryFlags) ([]*dns.Msg, error) {
	return ConcurrentLookup(ctx, dst, questions, flags, r.query, r.clientOptions.Logger)
}

// query takes a dns.Question and sends them to DNS Server specified in server.
// It parses the Response from the server in a custom output format.
func (r *ClassicClient) query(ctx context.Context, dst Destination, question dns.Question, flags QueryFlags) (*dns.Msg, error) {

	var messages = prepareMessages(question, flags, r.clientOptions.Ndots, r.clientOptions.SearchList)

	// set TLS if enabled
	if r.clientOptions.UseTLS {
		r.client.Net = r.client.Net + "-tls"
		// Provide extra TLS config for doing/skipping hostname verification.
		r.client.TLSConfig = &tls.Config{
			ServerName:         dst.TLSHostname,
			InsecureSkipVerify: r.clientOpts.InsecureSkipVerify,
		}
	}
	
	for _, msg := range messages {
		r.clientOptions.Logger.Debug("Attempting to resolve",
			"domain", msg.Question[0].Name,
			"ndots", r.clientOptions.Ndots,
			"nameserver", r.server,
		)

		// Since the library doesn't include tcp.Dial time,
		// it's better to not rely on `rtt` provided here and calculate it ourselves.
		now := time.Now()

		in, _, err := r.client.ExchangeContext(ctx, &msg, r.server)
		if err != nil {
			if err == context.Canceled || err == context.DeadlineExceeded {
				return in, err
			}
			return in, err
		}

		// In case the response size exceeds 512 bytes (can happen with lot of TXT records),
		// fallback to TCP as with UDP the response is truncated. Fallback mechanism is in-line with `dig`.
		if in.Truncated {
			switch r.client.Net {
			case "udp":
				r.client.Net = "tcp"
			case "udp4":
				r.client.Net = "tcp4"
			case "udp6":
				r.client.Net = "tcp6"
			default:
				r.client.Net = "tcp"
			}
			r.clientOptions.Logger.Debug("Response truncated; retrying now", "protocol", r.client.Net)
			return r.query(ctx, dst, question, flags)
		}

		if len(output.Answers) > 0 || in.Rcode == dns.RcodeSuccess {
			// Stop iterating the searchlist.
			break
		}

		// Check if context is done after each iteration
		select {
		case <-ctx.Done():
			return in, ctx.Err()
		default:
			// Continue to next iteration
		}
	}
	return in, nil
}
