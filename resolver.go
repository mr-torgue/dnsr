package dnsr

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"
	"log/slog"

	"github.com/coredns/coredns/plugin"
	"github.com/mr-torgue/dnsr/pkg/models"
	"github.com/mr-torgue/dnsr/pkg/clients"
	"github.com/mr-torgue/dnsr/pkg/utils"
	"github.com/coredns/coredns/plugin/pkg/cache"
	"github.com/coredns/coredns/request"
	"github.com/miekg/dns"
)

// DNS Resolution default configuration.
var (
	Timeout             = 2000 * time.Millisecond
	TypicalResponseTime = 100 * time.Millisecond
	MaxRecursion        = 10
	MaxNameservers      = 2
	MaxIPs              = 2
	DefaultNttl			= 3600 * time.Second // 1 hours
	DefaultPttl			= 14400 * time.Second // 4 hours
	DefaultTCPRetry     = true
	DefaultClassicRetry = true
	DefaultDNSSEC	    = false
	DefaultStrategy     = "parallel"
)

// Resolver errors.
var (
	NXDOMAIN = fmt.Errorf("NXDOMAIN")

	ErrMaxRecursion = fmt.Errorf("maximum recursion depth reached: %d", MaxRecursion)
	ErrMaxIPs       = fmt.Errorf("maximum name server IPs queried: %d", MaxIPs)
	ErrNoARecords   = fmt.Errorf("no A records found for name server")
	ErrNoResponse   = fmt.Errorf("no responses received")
	ErrNegCache     = fmt.Errorf("cache hit was negative")
	ErrTimeout      = fmt.Errorf("timeout expired") // TODO: Timeouter interface? e.g. func (e) Timeout() bool { return true }
)

// Resolver implements a primitive, non-recursive, caching DNS resolver.
type Resolver struct {
	logger       *slog.Logger
	timeout      time.Duration
	cache        *Cache.Cache // uses the coredns cache plugin
	cacheWriter  *cache.ResponseWriter 
	pttl         time.Duration
	nttl         time.Duration
	clientType   string
	client       *clients.Client // supported: udp, tcp, doh, doq, tls, and dnscrypt
	tcpRetry     bool   // indicates if queries should be retried when the client fails
	classicRetry bool   
	dnssec       bool   // turn on/off dnssec validation
	strategy     string // supported: sequential and parallel
}

// Option specifies a configuration option for a Resolver.
type Option func(*Resolver)

// WithLogger specifies a logger
func WithLogger(logger *slog.Logger) Option {
	return func(r *Resolver) {
		// TODO should we add some more checks?
		r.logger = logger
	}
}

// WithTimeout specifies the timeout for network operations.
// The default value is Timeout.
func WithTimeout(timeout time.Duration) Option {
	return func(r *Resolver) {
		r.timeout = timeout
	}
}

func WithPttl(pttl time.Duration) Option {
	return func(r *Resolver) {
		r.pttl = pttl
	}
}

func WithNttl(nttl time.Duration) Option {
	return func(r *Resolver) {
		r.nttl = nttl
	}
}

// WithClientType specifies the clientType we use (default UDP).
func WithClientType(clientType string) Option {
	return func(r *Resolver) {
		r.clientType = clientType
	}
}

// WithTCPRetry specifies that requests should be retried with TCP if responses
// are truncated. The retry must still complete within the timeout or context deadline.
func WithTCPRetry() Option {
	return func(r *Resolver) {
		r.tcpRetry = true
	}
}

// WithClassicRetry indicates that if the DoQ/DoH/DNSCrypt model fails, we should fallback to UDP.
// TODO: add support for DoT as well
func WithClassicRetry() Option {
	return func(r *Resolver) {
		r.classicRetry = true
	}
}

// WithDNSSEC specifies that DNSSEC validation should be used.
func WithDNSSEC() Option {
	return func(r *Resolver) {
		r.dnssec = true
	}
}

// WithStrategy specifies the NS strategy, which is either parallel or sequential.
func WithStrategy(strategy string) Option {
	return func(r *Resolver) {
		r.strategy = DefaultStrategy
		if strategy == "sequential" || strategy == "parallel" {
			r.strategy = strategy
		}
	}
}

// NewResolver returns an initialized Resolver with options.
// By default, the returned Resolver will have cache capacity 0
// and the default network timeout (Timeout).
func NewResolver(options ...Option) *Resolver {
	// set default values
	r := &Resolver{ 
		timeout: Timeout, 
		pttl: DefaultPttl, 
		nttl: DefaultNttl, 
		tcpRetry: DefaultTCPRetry, 
		classicRetry: DefaultClassicRetry,
		dnssec: DefaultDNSSEC, 
		strategy: DefaultStrategy, 
	}
	// parse options
	for _, o := range options {
		o(r)
	}
	// initialize complex structures
	if r.logger == nil {
		r.logger = utils.InitLogger(true)
	}
	r.cache, r.cacheWriter = newCache(r.pttl, r.nttl)
	if r.cache == nil || r.cacheWriter == nil {
		r.logger.Debug("Could not initialize resolver cache!")
		return nil
	}
	clientConfig := clients.NewClientConfig(r.logger, r.clientType, r.timeout)
	r.client, err := LoadClient(clientConfig)
	if err != nil {
		r.logger.Debug("Could not initialize resolver client!")
		return nil		
	}
	r.logger.Debug("Resolver Config:", r)
	return r
}

// newCache returns a Cache and ResponseWriter object.
// We reuse the cache used in the CoreDNS plugin.
func newCache(pttl time.Duration, nttl time.Duration) (*Cache, *ResponseWriter) {
	c := New()
	c.pttl = pttl
	c.nttl = nttl

	crr := &ResponseWriter{ResponseWriter: nil, Cache: c}

	return c, crr
}

// getState returns a new state (Request) for a given query.
// The reason we don't use dns.Msg is that dns.Msg does not have a check for the DO flag.
func getState(qname string, qtype string) (*request.Request) {
	dtype := dns.StringToType[qtype]
	if dtype == 0 {
		dtype = dns.TypeA
	}
	var qmsg dns.Msg
	qmsg.SetQuestion(qname, dtype)
	return &request.Request{W: nil, Req: qmsg} // TODO can we do this?
}

// Resolve calls ResolveErr to find DNS records of type qtype for the domain qname.
// For nonexistent domains (NXDOMAIN), it will return an empty, non-nil slice.
func (r *Resolver) Resolve(state *request.Request) (*dns.Msg, error) {
	ctx, cancel := context.WithTimeout(context.Background(), r.timeout)
	defer cancel()
	return r.resolve(ctx, state, 0)
}

// resolve recursively resolves unitl depth is reached or answer is found.
func (r *Resolver) resolve(ctx context.Context, state *request.Request, depth int) (*dns.Msg, error) {
	if depth++; depth > MaxRecursion {
		r.logger.Debug("Max depth reached: ", depth)
		return nil, ErrMaxRecursion
	}
	qmsg = state.req

	item := r.cache.getIfNotStale(time.Now().UTC(), state, "") // TODO server string
	if item != nil {
		r.logger.Debug("Cache hit for query: ", state.Qname(), " ", state.Qtype())
		return item.toMsg(qmsg, time.Now().UTC(), state.Do(), qmsg.AuthenticatedData), nil // TODO reuse time or new time.Now().UTC()?
	}
	r.logger.Debug("Resolving query: ", state.Qname(), " ", state.Qtype(), "with depth: ", depth)
	start := time.Now()
	rmsg, err = r.iterateParents(ctx, state, depth)
	return rmsg, err
}

// iteraterParents loops over the parents of the target.
func (r *Resolver) iterateParents(ctx context.Context, state request.Request, depth int) (*dns.Msg, error) {
	chanMsgs := make(chan *dns.Msg, MaxNameservers)
	chanErrs := make(chan error, MaxNameservers)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	qname = state.Qname()
	qmsg = state.req
	for pname, ok := qname, true; ok; pname, ok = parent(pname) {
		// If we’re looking for [foo.com,NS], then move on to the parent ([com,NS])
		if pname == qname && qtype == "NS" {
			continue
		}

		// Only query TLDs against the root nameservers
		if pname == "." && dns.CountLabel(qname) != 1 {
			// fmt.Fprintf(os.Stderr, "Warning: non-TLD query at root: dig +norecurse %s %s\n", qname, qtype)
			return nil, nil
		}

		// Get nameservers
		nsState := r.getState(pname, "NS") // returns a new state
		nsrsp, err := r.resolve(ctx, nsState, depth)
		if err == NXDOMAIN || err == ErrTimeout || err == context.DeadlineExceeded {
			return nil, err
		}
		if err != nil {
			continue
		}

		// Check cache for specific queries
		if nsrsp != nil && qtype != "" {
			item := c.cache.getIfNotStale(time.Now().UTC(), nsrsp, "") 
			if item != nil {
				if item.Rcode == dns.RcodeSuccess {
					return item.toMsg(m, time.Now().UTC(), do, ad), nil
				} else {
					return nil, ErrNegCache
				}
			}
		}

		// Query all nameservers in parallel
		count := 0
		
		// RR format: https://github.com/miekg/dns/blob/d1539a788a12830620381c4cc6617762994f3fa1/dns.go#L31
		for i := 0; i < len(nsrsp.Answer) && count < MaxNameservers; i++ {
			nrr := nsrsp.Answer[i]
			if nrr.Header().Rrtype != "NS" {
				continue
			}

			go func(host string) {
				rsp, err := r.exchange(ctx, host, state, depth)
				if err != nil {
					chanErrs <- err
				} else {
					chanRRs <- rsp
				}
			}(nrr.Value) // TODO not sure what to put here....

			count++
		}

		queried := count

		// Wait for answer, error, or cancellation
		for ; count > 0; count-- {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case rrs := <-chanMsgs:
				ctx := context.WithoutCancel(ctx)
				cancel() // stop any other work here before recursing
				return r.resolveCNAMEs(ctx, state, nsrsp, depth)
			case err = <-chanErrs:
				if err == NXDOMAIN {
					return nil, err
				}
			}

		}

		// NS queries naturally recurse, so stop further iteration
		// when we found and queried nameservers for this parent.
		// Continue if no nameservers were found, to handle
		// multi-label delegations where a parent zone delegates
		// several labels down (e.g. in-addr.arpa).
		// See https://github.com/domainr/dnsr/issues/148
		if state.Qtype() == "NS" && queried > 0 {
			return nil, err
		}
	}

	return nil, ErrNoResponse
}

// exchange retrieves the IP address of the nameserver (NS) and sends the query (state).
// FIXME: support IPv6
func (r *Resolver) exchange(ctx context.Context, host, state request.Request, depth int) (*dns.Msg, error) {
	count := 0
	newState := r.newState(host, "A") // returns a new state
	arrs, err := r.resolve(ctx, newState, depth)
	// FIXME: should we do an IP address check here?
	if err != nil {
		return nil, err
	}
	for _, arr := range arrs.Answer {
		// FIXME: support AAAA records?
		if arr.Type != "A" {
			continue
		}

		// Never query more than MaxIPs for any nameserver
		if count++; count > MaxIPs {
			return nil, ErrMaxIPs
		}

		rsp, err := r.exchangeIP(ctx, host, arr.Value, state, depth) // TODO arr.value fix
		if err == nil || err == NXDOMAIN || err == ErrTimeout {
			return rsp, err
		}

		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}

	return nil, ErrNoARecords
}

var dialerDefault = &net.Dialer{}

func (r *Resolver) exchangeIP(ctx context.Context, host, ip, state request.Request, depth int) (*dns.Msg, error) {
	
	// Synchronously query this DNS server
	start := time.Now()
	timeout := r.timeout // belt and suspenders, since ctx has a deadline from ResolveErr
	if dl, ok := ctx.Deadline(); ok {
		if start.After(dl.Add(-TypicalResponseTime)) { // bail if we can't finish in time (start is too close to deadline)
			return nil, ErrTimeout
		}
		timeout = dl.Sub(start)
	}

	// lookup using the specified resolver client
	// this code is agnostic to which client is used 
	// ip should be WITHOUT port number, clients take care of this themselves
	// retransmission is implemented in the client
	flags := clients.QueryFlags{
		AD: state.Req.AuthenticatedData, 
		RD: false, // Recursion Desired
		DO: state.Do(), // DNSSEC OK
	}
	dst := clients.Destination{ Server: ip, TLSHostname: host } // TLSHostname is ignored in case of UDP/TCP
	rmsg, err := r.client.Lookup(ctx, dst, state.Req.Question, flags)
	var dur time.Duration // TODO remove (?)

	select {
	case <-ctx.Done(): // Finished too late
		logCancellation(host, &qmsg, rmsg, depth, dur, client.Timeout)
		return nil, ctx.Err()
	default:
		logExchange(host, &qmsg, rmsg, depth, dur, client.Timeout, err) // Log hostname instead of IP
	}
	if err != nil {
		return nil, err
	}

	// Cache the response message
	valid, k := key(state.Name(), rmsg, mt, state.Do(), state.Req.CheckingDisabled) // TODO what is mt
	if valid {
		// Insert cache entry to positive cache
		if rmsg.Rcode == dns.RcodeSuccess {
			r.writer.set(rmsg, k, mt, r.cache.pttl) 
		} else {
			r.writer.set(rmsg, k, mt, r.cache.nttl) 
		}
	} else {
		r.logger.Info("Could not add to cache!")
	}

	// Resolve IP addresses of nameservers if the response didn't include glue records.
	// This handles out-of-bailiwick (OOB) referrals where the nameserver is outside the
	// queried domain's hierarchy (e.g., pnnl.gov using adns1.es.net as its NS).
	// In OOB cases, the parent zone's server cannot provide glue records, so we must
	// resolve the NS address separately. See https://github.com/domainr/dnsr/issues/174
	if qtype == "NS" {
		for _, rr := range Rmsg.Answer {
			if rr.Type != "NS" {
				continue
			}
			newstate := getState(rr.Value, "A")
			item := r.cache.getIfNotStale(time.Now().UTC(), newstate, "") // TODO server string
			if err == NXDOMAIN {
				continue
			}
			if err != nil {
				break
			}
			if len(arrs) == 0 {
				// Try asking the current nameserver for the NS's A record (fast path).
				// This works when glue records are available or the NS is in-bailiwick.
				arrs, err = r.exchangeIP(ctx, host, ip, rr.Value, "A", depth+1)
				if err == NXDOMAIN {
					// The nameserver returned NXDOMAIN, which likely means out-of-bailiwick
					// (e.g., asking a .gov server for a .net address). This NXDOMAIN is
					// not authoritative, so remove it from cache and resolve from root instead.
					r.cache.deleteNX(rr.Value)
					arrs, err = r.resolve(ctx, rr.Value, "A", depth+1)
					if err == NXDOMAIN {
						// NS truly doesn't exist, try the next nameserver
						continue
					}
				}
				if err != nil {
					// On timeout or other transient errors, try the next nameserver
					continue
				}
			}
			rrs = append(rrs, arrs...)
		}
	}

	return rrs, nil
}

// resolveCNAMEs recurses if it receives a CNAME rr.
// returns both the CNAME and requested record
func (r *Resolver) resolveCNAMEs(ctx context.Context, state request.Request, cmsg *dns.Msg, depth int) (*dns.Msg, error) {
	for _, crr := range cmsg.Answer {
		if crr.Type != "CNAME" || crr.Name != qname {
			continue
		}
		logCNAME(crr.String(), depth)
		newstate = getState(crr.Value, qtype)
		crmsg, _ := r.resolve(ctx, newState, depth)
		crmsg.CopyTo(cmsg) // Todo verify if this works
	}
	return cmsg, nil
}
