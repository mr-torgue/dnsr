package clients

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
)

// DOQClient represents the config options for setting up a DOQ based client.
type DOQClient struct {
	config ClientConfig
	port		  int
	fallbackClient: ClassicClient,
}

// splitHostPort splits a host:port string and handles IPv6 addresses properly.
// Returns the host without port and brackets.
func splitHostPort(addr string) (host, port string, err error) {
	host, port, err = net.SplitHostPort(addr)
	if err != nil {
		return "", "", err
	}
	// Remove brackets from IPv6 addresses
	host = strings.Trim(host, "[]")
	return host, port, nil
}

// NewDOQClient accepts a nameserver address and configures a DOQ based client.
func NewDOQClient(config ClientConfig) (Client, error) {
	// create a fallback client
	var classicClient = nil
	if config.useUDPFallback {
		classicClientConfig := config
		classicClientConfig.clientType = models.UDPClient
		classicClient, err := NewClassicClient(classicClientConfig, ClassicClientOpts{ false, false})
	}

	return &DOQClient{
		config: config,
		port:          port,
		fallbackClient: classicClient,
	}, nil
}

// Lookup implements the Client interface
func (c *DOQClient) Lookup(ctx context.Context, dst Destination, questions []dns.Question, flags QueryFlags) ([]*dns.Msg, error) {
	return ConcurrentLookup(ctx, dst, questions, flags, c.query, c.config.Logger)
}

// query takes a dns.Question and sends them to DNS Server.
// It parses the Response from the server in a custom output format.
func (c *DOQClient) query(ctx context.Context, dst Destination, server string, question dns.Question, flags QueryFlags) (*dns.Msg, error) {
	var messages = prepareMessages(question, flags, r.clientOptions.Ndots, r.clientOptions.SearchList)

	// Extract hostname from server address for TLS verification
	// If TLSHostname is explicitly set via flag, use that; otherwise extract from server address
	tlsHostname := dst.TLSHostname
	if tlsHostname == "" {
		tlsHostname = dst.server // assumes that dst.server is NOT in format IP:port
	}
	tls = &tls.Config{
			NextProtos:         []string{"doq"},
			ServerName:         tlsHostname,
			InsecureSkipVerify: clientOpts.InsecureSkipVerify,
		}


	addr := net.JoinHostPort(dst.server, c.port)
	session, err := quic.DialAddr(ctx, dst.server, tls, nil)
	if err != nil {
		return nil, err
	}
	defer session.CloseWithError(quic.ApplicationErrorCode(quic.NoError), "")

	for _, msg := range messages {
		c.config.Logger.Debug("Attempting to resolve",
			"domain", msg.Question[0].Name,
			"ndots", c.config.Ndots,
			"nameserver", dst.server,
		)

		// ref: https://www.rfc-editor.org/rfc/rfc9250.html#name-dns-message-ids
		msg.Id = 0

		// get the DNS Message in wire format.
		b, err := msg.Pack()
		if err != nil {
			return nil, err
		}
		now := time.Now()

		stream, err := session.OpenStreamSync(ctx)
		if err != nil {
			return nil, err
		}

		msgLen := uint16(len(b))
		msgLenBytes := []byte{byte(msgLen >> 8), byte(msgLen & 0xFF)}
		if _, err = stream.Write(msgLenBytes); err != nil {
			return nil, err
		}
		// Make a QUIC request to the DNS server with the DNS message as wire format bytes in the body.
		if _, err = stream.Write(b); err != nil {
			return nil, err
		}

		// The client MUST send the DNS query over the selected stream, and MUST
		// indicate through the STREAM FIN mechanism that no further data will be
		// sent on that stream. Note, that stream.Close() closes the write-direction
		// of the stream, but does not prevent reading from it.
		// See: https://github.com/AdguardTeam/dnsproxy/blob/f901a5f4b9e8d5f143dce459067bc6614c6d927d/upstream/doq.go#L247-L254
		err = stream.Close()
		if err != nil {
			return nil, fmt.Errorf("unable to close quic stream: %w", err)
		}

		// Use a separate context with timeout for reading the response
		readCtx, cancel := context.WithTimeout(ctx, r.clientOptions.Timeout)
		defer cancel()

		var buf []byte
		errChan := make(chan error, 1)
		go func() {
			var err error
			buf, err = io.ReadAll(stream)
			errChan <- err
		}()

		select {
		case err := <-errChan:
			if err != nil {
				return nil, err
			}
		case <-readCtx.Done():
			return nil, fmt.Errorf("timeout reading response")
		}

		rtt := time.Since(now)

		if len(buf) < 2 {
			return nil, fmt.Errorf("response too short: got %d bytes, need at least 2", len(buf))
		}

		packetLen := binary.BigEndian.Uint16(buf[:2])
		if packetLen != uint16(len(buf[2:])) {
			return nil, fmt.Errorf("packet length mismatch")
		}
		if err = msg.Unpack(buf[2:]); err != nil {
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
