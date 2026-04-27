package dnsr

import (
	"context"
	"fmt"
	"net"
	"time"
	"log/slog"

	"github.com/mr-torgue/dnsr/pkg/clients"
	"github.com/mr-torgue/dnsr/pkg/utils"
	"github.com/mr-torgue/dnsr/pkg/cache"
	"github.com/miekg/dns"
)

// DNS Resolution default configuration.
var (
	Timeout             = 10
	TypicalResponseTime = 100 * time.Millisecond
	MaxRecursion        = 10
	MaxNameservers      = 2
	MaxIPs              = 2
	DefaultNttl			= 3600 // 1 hours
	DefaultPttl			= 14400 // 4 hours
	DefaultClientType   = "udp"
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
	ErrOnlyTLD      = fmt.Errorf("only TLD should query root servers")
	ErrNegCache     = fmt.Errorf("cache hit was negative")
	ErrTimeout      = fmt.Errorf("timeout expired") // TODO: Timeouter interface? e.g. func (e) Timeout() bool { return true }
)

// Resolver implements a primitive, non-recursive, caching DNS resolver.
type Resolver struct {
	logger       *slog.Logger
	timeout      time.Duration
	cache        *cache.Cache 
	pttl         time.Duration
	nttl         time.Duration
	clientType   string
	client       clients.Client // supported: udp, tcp, doh, doq, tls, and dnscrypt
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

// WithDebugLogger creates a logger in debug mode
func WithDebugLogger() Option {
	return func(r *Resolver) {
		r.logger = utils.InitLogger(true)
	}
}

// WithTimeout specifies the timeout for network operations.
// The default value is Timeout.
func WithTimeout(timeout time.Duration) Option {
	return func(r *Resolver) {
		r.timeout = timeout * time.Second
	}
}

func WithPttl(pttl time.Duration) Option {
	return func(r *Resolver) {
		r.pttl = pttl * time.Second
	}
}

func WithNttl(nttl time.Duration) Option {
	return func(r *Resolver) {
		r.nttl = nttl * time.Second
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
		timeout: time.Duration(Timeout) * time.Second, 
		pttl: time.Duration(DefaultPttl) * time.Second, 
		nttl: time.Duration(DefaultNttl) * time.Second, 
		clientType: DefaultClientType,
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
		r.logger = utils.InitLogger(false)
	}
	r.cache = cache.NewCache( 
		cache.WithLogger(r.logger),
		cache.WithPttl(time.Duration(r.pttl / time.Second)), 
		cache.WithNttl(time.Duration(r.nttl / time.Second)), 
		cache.WithExpire(), 
	)
	if r.cache == nil {
		r.logger.Debug("Could not initialize resolver cache!")
		return nil
	}
	clientConfig := clients.NewClientConfig(
		clients.WithLogger(r.logger),
		clients.WithClientType(r.clientType),
		clients.WithTimeout(time.Duration(r.timeout / time.Second)),
	)
	var err error
	r.client, err = clients.LoadClient(clientConfig)
	if err != nil {
		r.logger.Debug(fmt.Sprintf("Could not initialize resolver client: %s. Error: %s.", r.clientType, err))
		return nil		
	}
	r.logger.Debug(fmt.Sprintf("Resolver Config: %+v", r))
	return r
}

// Resolve calls ResolveErr to find DNS records of type qtype for the domain qname.
// For nonexistent domains (NXDOMAIN), it will return an empty, non-nil slice.
func (r *Resolver) Resolve(qmsg *dns.Msg) (*dns.Msg, error) {
	ctx, cancel := context.WithTimeout(context.Background(), r.timeout)
	defer cancel()
	return r.resolve(ctx, qmsg, 0)
}

// resolve recursively resolves unitl depth is reached or answer is found.
func (r *Resolver) resolve(ctx context.Context, qmsg *dns.Msg, depth int) (*dns.Msg, error) {
	if depth++; depth > MaxRecursion {
		r.logger.Debug(fmt.Sprintf("Max depth reached: %d", depth))
		return nil, ErrMaxRecursion
	}
	qname := utils.GetName(qmsg)
	qtype := utils.GetType(qmsg)
	dtype := dns.TypeToString[qtype]
	// check in cache
	rmsg := r.cache.Get(qmsg)
	if rmsg != nil {
		r.logger.Debug(fmt.Sprintf("[query %s %s] cache hit", qname, dtype))
		return rmsg, nil 
	}
	r.logger.Debug(fmt.Sprintf("[query %s %s] resolving with depth: %d", qname, dtype, depth))
	var err error
	// if not in cache, look for NS
	rmsg, err = r.iterateParents(ctx, qmsg, depth)
	r.logger.Debug(fmt.Sprintf("[query %s %s] answer: %t, error: %s ", qname, dtype, rmsg != nil, err))
	return rmsg, err
}

// iteraterParents loops over the parents of the target.
func (r *Resolver) iterateParents(ctx context.Context, qmsg *dns.Msg, depth int) (*dns.Msg, error) {
	chanMsgs := make(chan *dns.Msg, MaxNameservers)
	chanErrs := make(chan error, MaxNameservers)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	qname := utils.GetName(qmsg)
	qtype := utils.GetType(qmsg)
	dtype := dns.TypeToString[qtype]
	r.logger.Debug(fmt.Sprintf("[query %s %s] start iterating parents", qname, dtype))
	for pname, ok := qname, true; ok; pname, ok = parent(pname) {
		r.logger.Debug(fmt.Sprintf("[query %s %s] start iterating parent: %s", qname, dtype, pname))
		// If we’re looking for [foo.com,NS], then move on to the parent ([com,NS])
		if pname == qname && qtype == dns.TypeNS {
			continue
		}

		// Only query TLDs against the root nameservers
		if pname == "." && dns.CountLabel(qname) != 1 {
			// fmt.Fprintf(os.Stderr, "Warning: non-TLD query at root: dig +norecurse %s %s\n", qname, qtype)
			r.logger.Debug(fmt.Sprintf("[query %s %s] pname == . && dns.CountLabel(qname) != 1", qname, dtype)) 
			return nil, ErrOnlyTLD
		}

		// Get nameservers
		nsQmsg := utils.CreateQuestion(pname, "NS") 
		nsRmsg, err := r.resolve(ctx, nsQmsg, depth)
		if err == NXDOMAIN || err == ErrTimeout || err == context.DeadlineExceeded {
			return nil, err
		}
		// should make sure that nsRmsg is not nil
		if err != nil {
			continue
		}
		if err == nil && nsRmsg == nil {
			r.logger.Debug(fmt.Sprintf("[query %s NS] should not happen", pname))
		}

		r.logger.Debug(fmt.Sprintf("[query %s NS] found %d nameservers", pname, len(nsRmsg.Answer)))

		// Check cache for specific queries (it retrieves intermediate queries)
		if nsRmsg != nil {
			qtypeRmsg := r.cache.Get(qmsg)
			if qtypeRmsg != nil {
				r.logger.Debug(fmt.Sprintf("[query %s %s] cache hit", qname, dtype)) 
				return qtypeRmsg, nil 
			}
		}

		// Query all nameservers in parallel
		count := 0
		
		// RR format: https://github.com/miekg/dns/blob/d1539a788a12830620381c4cc6617762994f3fa1/dns.go#L31
		for i := 0; i < len(nsRmsg.Answer) && count < MaxNameservers; i++ {
			nrr := nsRmsg.Answer[i]
			if nrr.Header().Rrtype != dns.TypeNS {
				continue
			}

			go func(host string) {
				rsp, err := r.exchange(ctx, host, qmsg, depth)
				if err != nil {
					chanErrs <- err
				} else {
					chanMsgs <- rsp
				}
			}(utils.GetValue(nrr))

			count++
		}

		queried := count

		// Wait for answer, error, or cancellation
		for ; count > 0; count-- {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case rsp := <-chanMsgs:
				ctx := context.WithoutCancel(ctx)
				cancel() // stop any other work here before recursing
				rsp.Ns = nsRmsg.Answer // set NS results in the Auth section
				return r.resolveCNAMEs(ctx, qmsg, rsp, depth)
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
		if qtype == dns.TypeNS && queried > 0 {
			r.logger.Debug(fmt.Sprintf("[query %s %s] no nameservers found, error: %s", qname, dtype, err))
			return nil, err
		}
	}

	return nil, ErrNoResponse
}

// exchange retrieves the IP address of the nameserver (NS) and sends the query (state).
// FIXME: support IPv6
func (r *Resolver) exchange(ctx context.Context, host string, qmsg *dns.Msg, depth int) (*dns.Msg, error) {
	count := 0
	newQmsg := utils.CreateQuestion(host, "A") // returns a new state
	newRmsg, err := r.resolve(ctx, newQmsg, depth)
	// FIXME: should we do an IP address check here?
	if err != nil {
		return nil, err
	}
	for _, rr := range newRmsg.Answer {
		if rr.Header().Rrtype != dns.TypeA {
			continue
		}

		// Never query more than MaxIPs for any nameserver
		if count++; count > MaxIPs {
			return nil, ErrMaxIPs
		}

		rsp, err := r.exchangeIP(ctx, host, utils.GetValue(rr), qmsg, depth) 
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

func (r *Resolver) exchangeIP(ctx context.Context, host string, ip string, qmsg *dns.Msg, depth int) (*dns.Msg, error) {
	qname := utils.GetName(qmsg)
	qtype := utils.GetType(qmsg)
	dtype := dns.TypeToString[qtype]
	// Synchronously query this DNS server
	start := time.Now()
	if dl, ok := ctx.Deadline(); ok {
		if start.After(dl.Add(-TypicalResponseTime)) { // bail if we can't finish in time (start is too close to deadline)
			return nil, ErrTimeout
		}
	}

	// lookup using the specified resolver client
	// this code is agnostic to which client is used 
	// ip should be WITHOUT port number, clients take care of this themselves
	// retransmission is implemented in the client
	flags := clients.QueryFlags{
		AD: qmsg.AuthenticatedData, 
		RD: false, // Recursion Desired
		DO: utils.GetDo(qmsg), // DNSSEC OK
	}
	dst := clients.Destination{ Server: ip, TLSHostname: host } // TLSHostname is ignored in case of UDP/TCP
	rmsgs, err := r.client.Lookup(ctx, dst, qmsg.Question, flags)

	select {
	case <-ctx.Done(): // Finished too late
		r.logger.Debug(fmt.Sprintf("[query %s %s] timeout, err: %s", qname, dtype, ctx.Err()))
		return nil, ctx.Err()
	default:
		r.logger.Debug(fmt.Sprintf("[query %s %s] asking %s (ip: %s) using %s client", qname, dtype, host, ip, r.clientType))
	}

	if err != nil {
		r.logger.Debug(fmt.Sprintf("[query %s %s] Could not connect to %s (ip: %s), error: %s", qname, dtype, host, ip, err))
		return nil, err
	}

	// FIXME: should multiple responses be possible?
	if len(rmsgs) > 1 {
		r.logger.Info(fmt.Sprintf("%s returned %d responses! Only expected one!", ip, len(rmsgs)))
	} else if len(rmsgs) == 0 {
		r.logger.Info(fmt.Sprintf("%s returned no response, error: %s", ip, err))
		return nil, err
	}

	rmsg := rmsgs[0]
	// Cache the response message
	r.cache.Add(rmsg)


	// Resolve IP addresses of nameservers if the response didn't include glue records.
	// This handles out-of-bailiwick (OOB) referrals where the nameserver is outside the
	// queried domain's hierarchy (e.g., pnnl.gov using adns1.es.net as its NS).
	// In OOB cases, the parent zone's server cannot provide glue records, so we must
	// resolve the NS address separately. See https://github.com/domainr/dnsr/issues/174
	if qtype == dns.TypeNS {
		for _, rr := range rmsg.Answer {
			if rr.Header().Rrtype != dns.TypeNS {
				continue
			}
			newQmsg := utils.CreateQuestion(utils.GetValue(rr), "A")
			newRmsg := r.cache.Get(newQmsg)
			if newRmsg != nil {
				r.logger.Debug(fmt.Sprintf("Found %s (A) in cache", utils.GetValue(rr)))
				// NXDOMAIN: keep going
				if newRmsg.Rcode == dns.RcodeNameError {
					continue
				} 
				// error: stop looking
				if newRmsg.Rcode != dns.RcodeSuccess {
					break
				}
			}
			if len(newRmsg.Answer) == 0 {
				// Try asking the current nameserver for the NS's A record (fast path).
				// This works when glue records are available or the NS is in-bailiwick.
				newRmsg, err = r.exchangeIP(ctx, host, ip, newQmsg, depth+1)
				if err == NXDOMAIN {
					// The nameserver returned NXDOMAIN, which likely means out-of-bailiwick
					// (e.g., asking a .gov server for a .net address). This NXDOMAIN is
					// not authoritative, so remove it from cache and resolve from root instead.
					r.cache.Delete(newRmsg) // TODO: determine if this is needed
					newRmsg, err = r.resolve(ctx, newQmsg, depth+1)
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
			rmsg.Extra = append(rmsg.Extra, newRmsg.Answer...)
		}
	}
	
	return rmsg, nil
}

// resolveCNAMEs recurses if it receives a CNAME rr in the response (rmsg).
// Returns both the CNAME and requested record type. The original query is stored in qmsg.
func (r *Resolver) resolveCNAMEs(ctx context.Context, qmsg *dns.Msg, rmsg *dns.Msg, depth int) (*dns.Msg, error) {
	qname := utils.GetName(qmsg)
	for _, rr := range rmsg.Answer {
		if rr.Header().Rrtype != dns.TypeCNAME || rr.Header().Name != qname {
			continue
		}
		r.logger.Debug(fmt.Sprintf("Resolving CNAME for %s", rr.Header().Name))
		cnameQmsg := utils.CreateQuestion(utils.GetValue(rr), "CNAME")
		cnameRmsg, _ := r.resolve(ctx, cnameQmsg, depth)
		// add to answer section
		for _, cnameRr := range cnameRmsg.Answer {
			rmsg.Answer = append(rmsg.Answer, cnameRr)
		}
	}
	return rmsg, nil
}