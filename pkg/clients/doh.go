package clients

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"net"
	"time"

	"github.com/mr-torgue/dnsr/pkg/models"
	"github.com/mr-torgue/dnsr/pkg/clients"
	"github.com/miekg/dns"
)

// DOHClient represents the config options for setting up a DOH based client.
type DOHClient struct {
	config ClientConfig
	port		 int
	fallbackClient ClassicClient
}

// NewDOHClient returns a DOHClient
func NewDOHClient(config ClientConfig) (Client, error) {
	// create a fallback client
	var classicClient = nil
	if config.useUDPFallback {
		classicClientConfig := config
		classicClientConfig.clientType = models.UDPClient
		classicClient, err := NewClassicClient(classicClientConfig, ClassicClientOpts{ false, false})
	}

	return &DOHClient{
		config: ClientConfig,
		port: models.DefaultDOHPort,
		fallbackClient: classicClient,
	}, nil
}

// Lookup implements the Client interface
func (c *DOHClient) Lookup(ctx context.Context, dst Destination, questions []dns.Question, flags QueryFlags) ([]*dns.Msg, error) {
	return ConcurrentLookup(ctx, dst, questions, flags, r.query, r.resolverOptions.Logger)
}

// query takes a dns.Question and sends them to DNS Server.
// It parses the Response from the server in a custom output format.
func (c *DOHClient) query(ctx context.Context, dst Destination, question dns.Question, flags QueryFlags) (*dns.Msg, error) {
	var messages = prepareMessages(question, flags, c.config.Ndots, c.config.SearchList)
	
	// do basic validation and setup https connection
	addr := net.JoinHostPort(dst.server, r.port)
	u, err := url.ParseRequestURI(addr)
	if err != nil {
		return nil, fmt.Errorf("%s is not a valid HTTPS nameserver", addr)
	}
	if u.Scheme != "https" {
		return nil, fmt.Errorf("missing https in %s", addr)
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{
		ServerName:         dst.TLSHostname,
		InsecureSkipVerify: c.config.InsecureSkipVerify,
	}
	httpClient := &http.Client{
		Timeout:   c.config.Timeout,
		Transport: transport,
	}

	for _, msg := range messages {
		c.config.Logger.Debug("Attempting to resolve",
			"domain", msg.Question[0].Name,
			"ndots", c.config.Ndots,
			"nameserver", addr,
		)
		// get the DNS Message in wire format.
		b, err := msg.Pack()
		if err != nil {
			return nil, err
		}
		now := time.Now()

		// Create a new request with the context
		req, err := http.NewRequestWithContext(ctx, "POST", addr, bytes.NewBuffer(b))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/dns-message")

		// Make an HTTP POST request to the DNS server with the DNS message as wire format bytes in the body.
		resp, err := httpClient.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusMethodNotAllowed {
			url, err := url.Parse(r.server)
			if err != nil {
				return nil, err
			}
			url.RawQuery = fmt.Sprintf("dns=%v", base64.RawURLEncoding.EncodeToString(b))

			req, err = http.NewRequestWithContext(ctx, "GET", url.String(), nil)
			if err != nil {
				return nil, err
			}
			resp, err = httpClient.Do(req)
			if err != nil {
				return nil, err
			}
			defer resp.Body.Close()
		}
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("error from nameserver %s", resp.Status)
		}
		rtt := time.Since(now)

		// if debug, extract the response headers
		for header, value := range resp.Header {
			r.resolverOptions.Logger.Debug("DOH response header", header, value)
		}

		// extract the binary response in DNS Message.
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}

		err = msg.Unpack(body)
		if err != nil {
			return nil, err
		}

		if msg.Rcode == dns.RcodeSuccess {
			// stop iterating the searchlist.
			break
		}

		// Check if context is done after each iteration
		select {
		case <-ctx.Done():
			return msg, ctx.Err()
		default:
			// Continue to next iteration
		}
	}
	return msg, nil
}
