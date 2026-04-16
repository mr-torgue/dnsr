package clients

import (
	"context"
	"crypto/tls"
	"time"
	"net"
	"fmt"

	"github.com/mr-torgue/dnsr/pkg/models"
	"github.com/miekg/dns"
)

// ClassicClient represents the config options for setting up a Client.
type ClassicClient struct {
	client          *dns.Client
	config   		ClientConfig
	opts 			ClassicClientOpts
	port 			string
}

// ClassicClientOpts holds options for setting up a Classic client.
type ClassicClientOpts struct {
	UseTLS bool
	UseTCP bool
}

// NewClassicClient accepts a list of nameservers and configures a DNS client.
func NewClassicClient(config ClientConfig, opts ClassicClientOpts) (Client, error) {
	net := "udp"
	port := models.DefaultUDPPort
	client := &dns.Client{
		Timeout: config.Timeout,
		Net:     "udp",
	}

	if opts.UseTCP {
		net = "tcp"
		port = models.DefaultTCPPort
	}

	if config.UseIPv4 {
		net = net + "4"
	} else if config.UseIPv6 {
		net = net + "6"
	}

	if opts.UseTLS {
		port = models.DefaultTLSPort
	}

	client.Net = net

	return &ClassicClient{
		client: client,
		config: config,
		opts  : opts, 
		port: port,
	}, nil
}

// Lookup implements the Client interface
func (c *ClassicClient) Lookup(ctx context.Context, dst Destination, questions []dns.Question, flags QueryFlags) ([]*dns.Msg, error) {
	return ConcurrentLookup(ctx, dst, questions, flags, c.query, c.config.Logger)
}

// query takes a dns.Question and sends them to DNS Server specified in server.
// It parses the Response from the server in a custom output format.
func (c *ClassicClient) query(ctx context.Context, dst Destination, question dns.Question, flags QueryFlags) (*dns.Msg, error) {
	var (
		in      *dns.Msg
		messages = prepareMessages(question, flags, c.config.Ndots, c.config.SearchList)
	)

	// set TLS if enabled
	if c.opts.UseTLS {
		c.client.Net = c.client.Net + "-tls"
		// Provide extra TLS config for doing/skipping hostname verification.
		c.client.TLSConfig = &tls.Config{
			ServerName:         dst.TLSHostname,
			InsecureSkipVerify: c.config.InsecureSkipVerify,
		}
	}
	
	addr := net.JoinHostPort(dst.server, c.port)
	for _, msg := range messages {
		c.config.Logger.Debug("Attempting to resolve",
			"domain", msg.Question[0].Name,
			"ndots", c.config.Ndots,
			"nameserver", addr,
		)

		// Since the library doesn't include tcp.Dial time,
		// it's better to not rely on `rtt` provided here and calculate it ourselves.
		//now := time.Now()

		in, _, err := c.client.ExchangeContext(ctx, &msg, dst.server)
		if err != nil {
			if err == context.Canceled || err == context.DeadlineExceeded {
				return in, err
			}
			return in, err
		}

		// In case the response size exceeds 512 bytes (can happen with lot of TXT records),
		// fallback to TCP as with UDP the response is truncated. Fallback mechanism is in-line with `dig`.
		if in.Truncated {
			if !c.config.useTCPFallback {
				c.config.Logger.Debug("Truncated msg and TCP retransmission disabled!")
				return in, fmt.Errorf("truncated response and TCP retransmission disabled")
			}
			switch c.client.Net {
			case "udp":
				c.client.Net = "tcp"
			case "udp4":
				c.client.Net = "tcp4"
			case "udp6":
				c.client.Net = "tcp6"
			default:
				c.client.Net = "tcp"
			}
			c.config.Logger.Debug("Response truncated; retrying now", "protocol", c.client.Net)
			return c.query(ctx, dst, question, flags)
		}

		if in.Rcode == dns.RcodeSuccess {
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
