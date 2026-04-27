package clients

import (
	"context"
	"crypto/tls"
//	"time"
	"net"
	"fmt"

	"github.com/mr-torgue/dnsr/pkg/models"
	"github.com/miekg/dns"
)

// ClassicClient represents the config options for setting up a Client.
type ClassicClient struct {
	client          *dns.Client
	config   		*ClientConfig
	opts 			ClassicClientOpts
	port 			string
}

// ClassicClientOpts holds options for setting up a Classic client.
type ClassicClientOpts struct {
	UseTLS bool
	UseTCP bool
}

// NewClassicClient accepts a list of nameservers and configures a DNS client.
func NewClassicClient(config *ClientConfig, opts ClassicClientOpts) (Client, error) {
	net := "udp"
	port := models.DefaultUDPPort
	client := &dns.Client{
		Timeout: config.timeout,
		Net:     "udp",
	}

	if opts.UseTCP {
		net = "tcp"
		port = models.DefaultTCPPort
	}

	if config.useIPv4 {
		net = net + "4"
	} else if config.useIPv6 {
		net = net + "6"
	}

	if opts.UseTLS {
		net = net + "-tls"
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
	return ConcurrentLookup(ctx, dst, questions, flags, c.query, c.config.logger)
}

// query takes a dns.Question and sends them to DNS Server specified in server.
// It parses the Response from the server in a custom output format.
func (c *ClassicClient) query(ctx context.Context, dst Destination, question dns.Question, flags QueryFlags) (*dns.Msg, error) {
	var (
		rsp      *dns.Msg
		messages = prepareMessages(question, flags, c.config.ndots, c.config.searchList)
	)


	// set a timeout for the query
	connCtx, cancelConn := context.WithTimeout(ctx, c.config.timeout)
	defer cancelConn()

	// set TLS if enabled (make sure that it uses client.Net = xxx-tls)
	if c.opts.UseTLS {
		// Provide extra TLS config for doing/skipping hostname verification.
		c.client.TLSConfig = &tls.Config{
			ServerName:         dst.TLSHostname,
			InsecureSkipVerify: c.config.insecureSkipVerify,
		}
	}
	
	addr := net.JoinHostPort(dst.Server, c.port)
	for _, msg := range messages {
		c.config.logger.Debug("Attempting to resolve",
			"domain", msg.Question[0].Name,
			"ndots", c.config.ndots,
			"nameserver", addr,
			"flags", flags,
			"RD", msg.MsgHdr.RecursionDesired,
			"msg", msg.String(),
		)

		// Since the library doesn't include tcp.Dial time,
		// it's better to not rely on `rtt` provided here and calculate it ourselves.
		//now := time.Now()

		in, _, err := c.client.ExchangeContext(connCtx, &msg, addr)
		if err != nil {
			if err == context.Canceled || err == context.DeadlineExceeded {
				return rsp, err
			}
			return rsp, err
		}

		// In case the response size exceeds 512 bytes (can happen with lot of TXT records),
		// fallback to TCP as with UDP the response is truncated. Fallback mechanism is in-line with `dig`.
		if in.Truncated {
			if !c.config.useTCPFallback {
				c.config.logger.Debug("Truncated msg and TCP retransmission disabled!")
				return rsp, fmt.Errorf("truncated response and TCP retransmission disabled")
			}
			oldNet := c.client.Net
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
			c.config.logger.Debug("Response truncated; retrying now", "protocol", c.client.Net)
			in, _, err = c.client.ExchangeContext(connCtx, &msg, addr)
			c.client.Net = oldNet // reset
			if err != nil {
				if err == context.Canceled || err == context.DeadlineExceeded {
					return rsp, err
				}
				return rsp, err
			}
			//return c.query(connCtx, dst, question, flags)
		}

		rsp = in
		if in.Rcode == dns.RcodeSuccess {
			// Stop iterating the searchlist.
			break
		}

		// Check if context is done after each iteration
		select {
		case <-connCtx.Done():
			return rsp, connCtx.Err()
		default:
			// Continue to next iteration
		}
	}
	return rsp, nil
}
