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
//	"time"

	"github.com/mr-torgue/dnsr/pkg/models"
	"github.com/miekg/dns"
)

// DOHClient represents the config options for setting up a DOH based client.
type DOHClient struct {
	config *ClientConfig
	port		 string
	fallbackClient Client
}

// NewDOHClient returns a DOHClient
func NewDOHClient(config *ClientConfig) (Client, error) {
	// create a fallback client
	var classicClient Client
	var err error
	if config.useUDPFallback {
		classicClientConfig := config
		classicClientConfig.clientType = models.UDPClient
		classicClient, err = NewClassicClient(classicClientConfig, ClassicClientOpts{ UseTLS: false, UseTCP: false })
		if err != nil {
			config.logger.Info("Could not initialize fallback client in DoH!\n")
		}
	}

	return &DOHClient{
		config: config,
		port: models.DefaultDOHPort,
		fallbackClient: classicClient,
	}, nil
}

// Lookup implements the Client interface
func (c *DOHClient) Lookup(ctx context.Context, dst Destination, questions []dns.Question, flags QueryFlags) ([]*dns.Msg, error) {
	return ConcurrentLookup(ctx, dst, questions, flags, c.query, c.config.logger)
}

// query takes a dns.Question and sends them to DNS Server.
// It parses the Response from the server in a custom output format.
func (c *DOHClient) query(ctx context.Context, dst Destination, question dns.Question, flags QueryFlags) (*dns.Msg, error) {
	var (
		//msg      *dns.Msg
		messages = prepareMessages(question, flags, c.config.ndots, c.config.searchList)
	)
	
	// do basic validation and setup https connection
	addr := "https://" + net.JoinHostPort(dst.Server, c.port)
	u, err := url.ParseRequestURI(addr)
	if err != nil {
		return nil, fmt.Errorf("%s is not a valid HTTPS nameserver: %s", addr, err)
	}
	if u.Scheme != "https" {
		return nil, fmt.Errorf("missing https in %s", addr)
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{
		ServerName:         dst.TLSHostname,
		InsecureSkipVerify: c.config.insecureSkipVerify,
	}
	httpClient := &http.Client{
		Timeout:   c.config.timeout,
		Transport: transport,
	}

	for _, msg := range messages {
		c.config.logger.Debug("Attempting to resolve",
			"domain", msg.Question[0].Name,
			"ndots", c.config.ndots,
			"nameserver", addr,
		)
		// get the DNS Message in wire format.
		b, err := msg.Pack()
		if err != nil {
			c.config.logger.Debug("Could not pack msg %s. Error: %s", msg.String(), err)
			return nil, err
		}
		//now := time.Now()

		// Create a new request with the context
		req, err := http.NewRequestWithContext(ctx, "POST", addr, bytes.NewBuffer(b))
		if err != nil {
			// fallback if enabled
			if c.config.useUDPFallback {
				return c.fallbackClient.query(ctx, dst, question, flags)
			}
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
			url, err := url.Parse(addr)
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
		//rtt := time.Since(now)

		// if debug, extract the response headers
		for header, value := range resp.Header {
			c.config.logger.Debug("DOH response header", header, value)
		}

		// extract the binary response in DNS Message.
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}

		err = msg.Unpack(body)
		if err != nil {
			c.config.logger.Debug("Could not unpack body")
			//if c.config.useUDPFallback {
			//	return c.fallbackClient.query(ctx, dst, question, flags)
			//}
			return nil, fmt.Errorf("unpack error. Server does not support DoH.")
		}

		if msg.Rcode == dns.RcodeSuccess {
			// stop iterating the searchlist.
			return &msg, nil
		}

		// Check if context is done after each iteration
		select {
		case <-ctx.Done():
			return &msg, ctx.Err()
		default:
			// Continue to next iteration
		}
	}
	return nil, nil
}
