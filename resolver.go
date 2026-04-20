package dnsr

import (
	"context"
	"fmt"
	"net"
	"time"
	"log/slog"
	"strings"

	"github.com/mr-torgue/dnsr/pkg/clients"
	"github.com/mr-torgue/dnsr/pkg/utils"
	"github.com/mr-torgue/dnsr/pkg/cache"
	"github.com/miekg/dns"
)

// DNS Resolution default configuration.
var (
	Timeout             = 10 * time.Second
	TypicalResponseTime = 100 * time.Millisecond
	MaxRecursion        = 10
	MaxNameservers      = 2
	MaxIPs              = 2
	DefaultNttl			= 3600 * time.Second // 1 hours
	DefaultPttl			= 14400 * time.Second // 4 hours
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
		r.logger = utils.InitLogger(true)
	}
	r.cache = cache.NewCache( cache.WithPttl(r.pttl), cache.WithNttl(r.nttl), cache.WithExpire() )
	if r.cache == nil {
		r.logger.Debug("Could not initialize resolver cache!")
		//exit(1)
		return nil
	}
	clientConfig := clients.NewClientConfig(r.logger, r.clientType, r.timeout)
	var err error
	r.client, err = clients.LoadClient(clientConfig)
	if err != nil {
		r.logger.Debug(fmt.Sprintf("Could not initialize resolver client: %s. Error: %s.", r.clientType, err))
		return nil		
	}
	r.logger.Debug(fmt.Sprintf("Resolver Config: %+v", r))
	return r
}

// getQuestion returns a new dns message for a given query.
func getQuestion(qname string, qtype string) (*dns.Msg) {
	dtype := dns.StringToType[qtype]
	if dtype == 0 {
		dtype = dns.TypeA
	}
	var qmsg dns.Msg
	qmsg.SetQuestion(qname, dtype)
	return &qmsg
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
	qname := name(qmsg)
	qtype := qtype(qmsg)
	rmsg := r.cache.Get(qmsg) 
	if rmsg != nil {
		r.logger.Debug(fmt.Sprintf("Cache hit for query: %s (%d)", qname, qtype)) // TODO: string instead of int
		return rmsg, nil 
	}
	r.logger.Debug(fmt.Sprintf("Resolving query: %s (%d) with depth %d", qname, qtype, depth))
	var err error
	rmsg, err = r.iterateParents(ctx, qmsg, depth)
	return rmsg, err
}

// iteraterParents loops over the parents of the target.
func (r *Resolver) iterateParents(ctx context.Context, qmsg *dns.Msg, depth int) (*dns.Msg, error) {
	chanMsgs := make(chan *dns.Msg, MaxNameservers)
	chanErrs := make(chan error, MaxNameservers)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	qname := name(qmsg)
	qtype := qtype(qmsg)
	for pname, ok := qname, true; ok; pname, ok = parent(pname) {
		// If we’re looking for [foo.com,NS], then move on to the parent ([com,NS])
		if pname == qname && qtype == dns.TypeNS {
			continue
		}

		// Only query TLDs against the root nameservers
		if pname == "." && dns.CountLabel(qname) != 1 {
			// fmt.Fprintf(os.Stderr, "Warning: non-TLD query at root: dig +norecurse %s %s\n", qname, qtype)
			return nil, nil
		}

		// Get nameservers
		nsQmsg := getQuestion(pname, "NS") // returns a new state
		nsRmsg, err := r.resolve(ctx, nsQmsg, depth)
		if err == NXDOMAIN || err == ErrTimeout || err == context.DeadlineExceeded {
			return nil, err
		}
		if err != nil {
			continue
		}

		// Check cache for specific queries
		if nsRmsg != nil && qtype != 0 {
			qtypeRmsg := r.cache.Get(nsRmsg)
			if qtypeRmsg != nil {
				return qtypeRmsg, nil // TODO don't return negative cache
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
			}(value(nrr))

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
			return nil, err
		}
	}

	return nil, ErrNoResponse
}

// exchange retrieves the IP address of the nameserver (NS) and sends the query (state).
// FIXME: support IPv6
func (r *Resolver) exchange(ctx context.Context, host string, qmsg *dns.Msg, depth int) (*dns.Msg, error) {
	count := 0
	newQmsg := getQuestion(host, "A") // returns a new state
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

		rsp, err := r.exchangeIP(ctx, host, value(rr), qmsg, depth) 
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
	
	qtype := qtype(qmsg)
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
		DO: do(qmsg), // DNSSEC OK
	}
	dst := clients.Destination{ Server: ip, TLSHostname: host } // TLSHostname is ignored in case of UDP/TCP
	rmsgs, err := r.client.Lookup(ctx, dst, qmsg.Question, flags)

	select {
	case <-ctx.Done(): // Finished too late
		return nil, ctx.Err()
	default:
		// TODO add logging
	}
	if err != nil {
		return nil, err
	}

	// FIXME: should multiple responses be possible?
	if len(rmsgs) > 1 {
		r.logger.Info(fmt.Sprintf("%s returned %d responses! Only expected one!", ip, len(rmsgs)))
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
			newQmsg := getQuestion(value(rr), "A")
			newRmsg := r.cache.Get(newQmsg)
			if err == NXDOMAIN {
				continue
			}
			if err != nil {
				break
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
		}
	}
	
	return rmsg, nil
}

// resolveCNAMEs recurses if it receives a CNAME rr in the response (cmsg).
// Returns both the CNAME and requested record type. The original query is stored in qmsg.
func (r *Resolver) resolveCNAMEs(ctx context.Context, qmsg *dns.Msg, cmsg *dns.Msg, depth int) (*dns.Msg, error) {
	qname := name(cmsg)
	for _, crr := range cmsg.Answer {
		if crr.Header().Rrtype != dns.TypeCNAME || crr.Header().Name != qname {
			continue
		}
		cqmsg := getQuestion(value(crr), "CNAME")
		crmsg, _ := r.resolve(ctx, cqmsg, depth)
		crmsg.CopyTo(cmsg) // TODO: verify if this works
	}
	return cmsg, nil
}

// FIXME move these functions to another file

// copied from https://github.com/coredns/coredns/blob/master/request/request.go#L275 
func name(msg *dns.Msg) string {
	if msg == nil || len(msg.Question) == 0 {
		return "."
	}
	return strings.ToLower(dns.Name(msg.Question[0].Name).String())
}

// copied from https://github.com/coredns/coredns/blob/master/request/request.go#L260
func qtype(msg *dns.Msg) uint16 {
	if msg == nil || len(msg.Question) == 0 {
		return 0
	}
	return msg.Question[0].Qtype
}

func do(msg *dns.Msg) bool {
	opt := msg.IsEdns0()
	if opt == nil {
		return false
	}
	return opt.Do()
}

// value returns the value of RR.
// FIXME is there a better way of doing this? Technically, I think it is only used for NS/A/AAAA/CNAME records
func value(rr dns.RR) string {
	switch t := rr.(type) {
	case *dns.SOA:
		return toLowerFQDN(t.Ns)
	case *dns.NS:
		return toLowerFQDN(t.Ns)
	case *dns.CNAME:
		return toLowerFQDN(t.Target)
	case *dns.A:
		return t.A.String()
	case *dns.AAAA:
		return t.AAAA.String()
	case *dns.TXT:
		return strings.Join(t.Txt, "\t")
	default:
		fields := strings.Fields(rr.String())
		if len(fields) >= 4 {
			return strings.Join(fields[4:], "\t")
		}
	}
	return ""
}	