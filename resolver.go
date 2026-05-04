package dnsr

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"
	"log/slog"

	"github.com/mr-torgue/dnsr/pkg/clients"
	"github.com/mr-torgue/dnsr/pkg/utils"
	"github.com/mr-torgue/dnsr/pkg/cache"
	"github.com/miekg/dns"
)

// DNS Resolution configuration.
var (
	Timeout             = 10 * time.Second
	ClientTimeout		= 2 * time.Second
	TypicalResponseTime = 100 * time.Millisecond
	MaxRecursion        = 10
	MaxNameservers      = 2
	MaxIPs              = 2
	DefaultClientType   = "udp"
	DefaultCapacity     = 10000
	DefaultExpire       = true
	DefaultTCPRetry     = true
	DefaultClassicRetry = true
	DefaultDNSSEC	    = false
	DefaultEDNS		 	= false
	DefaultUDPSize      = uint16(1232)
	DefaultStrategy     = "parallel"
	DefaultRootfile     = "named.root"
)

// Resolver errors.
var (
	NXDOMAIN = fmt.Errorf("NXDOMAIN")

	ErrMaxRecursion = fmt.Errorf("maximum recursion depth reached: %d", MaxRecursion)
	ErrMaxIPs       = fmt.Errorf("maximum name server IPs queried: %d", MaxIPs)
	ErrNoARecords   = fmt.Errorf("no A records found for name server")
	ErrNoResponse   = fmt.Errorf("no responses received")
	ErrTimeout      = fmt.Errorf("timeout expired") // TODO: Timeouter interface? e.g. func (e) Timeout() bool { return true }
	ErrNoCache 		= fmt.Errorf("could not initialize cache")
	ErrNoRootcache	= fmt.Errorf("could not initialize rootcache")
	ErrNoClient		= fmt.Errorf("could not initialize client")
)

// A ContextDialer implements the DialContext method, e.g. net.Dialer.
type ContextDialer interface {
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
}

// Option specifies a configuration option for a Resolver.
type Option func(*Resolver)

// WithLogger specifies a logger
func WithLogger(logger *slog.Logger) Option {
	return func(r *Resolver) {
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
// The default value is Timeout. Duration is provided in string
// format, such as "10s" or "2m".
func WithTimeout(timeoutStr string) Option {
    timeout, err := time.ParseDuration(timeoutStr)
    if err != nil {
        timeout = Timeout
    }
    return func(r *Resolver) {
        r.timeout = timeout
    }
}

// WithCapacity specifies a cache with capacity cap.
func WithCapacity(capacity int) Option {
	return func(r *Resolver) {
		r.capacity = capacity
	}
}

// WithRootfile specifies a cache with capacity cap.
func WithRootfile(filename string) Option {
	return func(r *Resolver) {
		r.rootcache = cache.LoadRootfile(filename)
	}
}


// WithExpire specifies that the Resolver will delete stale cache entries.
func WithExpire(expire bool) Option {
	return func(r *Resolver) {
		r.expire = expire
	}
}

// WithClientType specifies the client that the resolver will use to make queries.
func WithClientType(clientType string) Option {
	return func(r *Resolver) {
		r.clientType = clientType
	}
}

// WithClientTimeout specifies the timeout for client connections.
// Duration is provided in string format, such as "10s" or "2m".
func WithClientTimeout(timeoutStr string) Option {
    timeout, err := time.ParseDuration(timeoutStr)
    if err != nil {
        timeout = Timeout
    }
    return func(r *Resolver) {
        r.clientTimeout = timeout
    }
}

// WithTCPRetry specifies that requests should be retried with TCP if responses
// are truncated. The retry must still complete within the timeout or context deadline.
func WithTCPRetry(tcpRetry bool) Option {
	return func(r *Resolver) {
		r.tcpRetry = tcpRetry
	}
}

// WithClassicRetry indicates that if the DoQ/DoH/DNSCrypt model fails, we should fallback to UDP.
// TODO: add support for DoT as well
func WithClassicRetry(classicRetry bool) Option {
	return func(r *Resolver) {
		r.classicRetry = classicRetry
	}
}

// WithDNSSEC specifies that DNSSEC validation should be used.
func WithDNSSEC(dnssec bool) Option {
	return func(r *Resolver) {
		r.dnssec = dnssec
	}
}

// WithEDNS specifies that EDNS is enabledd.
func WithEDNS(edns bool) Option {
	return func(r *Resolver) {
		r.edns = edns
	}
}

// WithUDPSize specifies the EDNS UDP size.
func WithUDPSize(udpsize uint16) Option {
	return func(r *Resolver) {
		r.udpsize = udpsize
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

// Resolver implements a primitive, non-recursive, caching DNS resolver.
type Resolver struct {
	logger        *slog.Logger
	timeout       time.Duration
	// cache settings
	cache         *cache.Cache
	capacity      int
	expire        bool
	rootcache     *cache.Cache
	// client settings
	client        clients.Client // supported: udp, tcp, doh, doq, tls, and dnscrypt
	clientType    string
	clientTimeout time.Duration
	tcpRetry      bool   // indicates if queries should be retried when the client fails
	classicRetry  bool   
	dnssec        bool   // turn on/off dnssec validation
	edns 		  bool
	udpsize       uint16
	strategy      string // supported: sequential and parallel
} 

// NewResolver returns an initialized Resolver with options.
// By default, the returned Resolver will have cache capacity 0
// and the default network timeout (Timeout).
func NewResolver(options ...Option) *Resolver {
	// set default values
	r := &Resolver{ 
		timeout: Timeout,
		capacity: DefaultCapacity, 
		expire: DefaultExpire,
		clientType: DefaultClientType,
		clientTimeout: ClientTimeout,
		tcpRetry: DefaultTCPRetry, 
		classicRetry: DefaultClassicRetry,
		dnssec: DefaultDNSSEC, 
		edns: DefaultEDNS,
		udpsize: DefaultUDPSize,
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
		r.capacity,
		r.expire,
	)
	if r.cache == nil {
		panic(ErrNoCache)
	}
	clientConfig := clients.NewClientConfig(
		clients.WithLogger(r.logger),
		clients.WithClientType(r.clientType),
		clients.WithTimeout(r.clientTimeout),
	)
	var err error
	r.client, err = clients.LoadClient(clientConfig)
	if err != nil {
		r.logger.Debug(fmt.Sprintf("Could not initialize resolver client: %s. Switching to a UDP client.", r.clientType))
		clientConfig = clients.NewClientConfig()
		r.client, err = clients.LoadClient(clientConfig)
		if err != nil {
			panic(ErrNoClient)
		}
	}
	if r.rootcache == nil {
		r.rootcache = cache.LoadRootfile("named.root")
		if r.rootcache == nil {
			panic(ErrNoRootcache)
		}

	}
	r.logger.Debug(fmt.Sprintf("Resolver Config: %+v", r))
	return r
}

// New initializes a Resolver with the specified cache size.
// Deprecated: use NewResolver with Option(s) instead.
func New(cap int) *Resolver {
	return NewResolver(WithCapacity(cap))
}

// NewWithTimeout initializes a Resolver with the specified cache size and timeout.
// Deprecated: use NewResolver with Option(s) instead.
func NewWithTimeout(cap int, timeoutStr string) *Resolver {
	return NewResolver(WithCapacity(cap), WithTimeout(timeoutStr))
}

// NewExpiring initializes an expiring Resolver with the specified cache size.
// Deprecated: use NewResolver with Option(s) instead.
func NewExpiring(cap int) *Resolver {
	return NewResolver(WithCapacity(cap), WithExpire(true))
}

// NewExpiringWithTimeout initializes an expiring Resolved with the specified cache size and timeout.
// Deprecated: use NewResolver with Option(s) instead.
func NewExpiringWithTimeout(cap int, timeoutStr string) *Resolver {
	return NewResolver(WithCapacity(cap), WithTimeout(timeoutStr), WithExpire(true))
}

// Resolve calls ResolveErr to find DNS records of type qtype for the domain qname.
// For nonexistent domains (NXDOMAIN), it will return an empty, non-nil slice.
func (r *Resolver) Resolve(qname, qtype string) cache.RRs {
	rrs, err := r.ResolveErr(qname, qtype)
	if err == NXDOMAIN {
		return cache.EmptyRRs
	}
	if err != nil {
		return nil
	}
	return rrs
}

// ResolveErr finds DNS records of type qtype for the domain qname.
// For nonexistent domains, it will return an NXDOMAIN error.
// Specify an empty string in qtype to receive any DNS records found
// (currently A, AAAA, NS, CNAME, SOA, and TXT).
func (r *Resolver) ResolveErr(qname, qtype string) (cache.RRs, error) {
	ctx, cancel := context.WithTimeout(context.Background(), r.timeout)
	defer cancel()
	return r.resolve(ctx, utils.ToLowerFQDN(qname), qtype, 0)
}

// ResolveMsg returns a dns.Msg instead of a RRs. Basically, just wraps
// around r.resolve and converts the outcome to a dns.Msg.
func (r *Resolver) ResolveMsg(qmsg *dns.Msg) *dns.Msg {
	if qmsg != nil {
		qname := utils.GetName(qmsg)
		qtypeNr := utils.GetType(qmsg)
		qtype := dns.TypeToString[qtypeNr]
		rrs, err := r.ResolveErr(qname, qtype)

		r.logger.Debug(fmt.Sprintf("found %s", rrs))
		// prepare the answer
		var rmsg = new(dns.Msg)
		rmsg.SetReply(qmsg)
		// check if we received an answer
		if err == nil && len(rrs) > 0 {	
			// copy answer to Answer section
			cnameMap := make(map[string]cache.RR) // for verifying the CNAME chain
			answerName := ""
			for _, rr := range rrs {
				// check if the type matches (or CNAME)
				if rr.Type == qtype || rr.Type == "CNAME" {
					newrr := cache.ConvertDNSRR(rr)
					r.logger.Debug(fmt.Sprintf("Converting %s %s into %s", rr.Name, rr.Type, newrr.String()))
					if newrr != nil {
						rmsg.Answer = append(rmsg.Answer, newrr)
					}
					if rr.Type == "CNAME" {
						cnameMap[rr.Name] = rr
					} else {
						// we cannot have answers for 
						if answerName != "" && answerName != rr.Name {
							r.logger.Info(fmt.Sprintf("Found answers for differente qnames, got %s and %s", answerName, rr.Name))
							rmsg.Answer = nil
							rmsg.Rcode = dns.RcodeServerFailure 
							break
						}
						answerName = rr.Name
					}
				}
			}
			// if CNAME is found we have to verify the chain.
			// Would be easier if we can assume the responses are ordered, but lets not do that.
			name := utils.ToLowerFQDN(qname)
			for _, ok := cnameMap[name]; ok; _, ok = cnameMap[name] {
				name = cnameMap[name].Value
			}
			if name != answerName {
				r.logger.Info(fmt.Sprintf("CNAME chain invalid, expected %s but got %s", answerName, name))
				rmsg.Answer = nil
				rmsg.Rcode = dns.RcodeServerFailure 
			}

		} else if err == NXDOMAIN { 
			rmsg.Rcode = dns.RcodeNameError 
		} else {
			rmsg.Rcode = dns.RcodeServerFailure 
		}
		return rmsg
	} 
	return nil
}

// ResolveCtx finds DNS records of type qtype for the domain qname using
// the supplied context. Requests may time out earlier if timeout is
// shorter than a deadline set in ctx.
// For nonexistent domains, it will return an NXDOMAIN error.
// Specify an empty string in qtype to receive any DNS records found
// (currently A, AAAA, NS, CNAME, SOA, and TXT).
// Deprecated: use ResolveContext.
func (r *Resolver) ResolveCtx(ctx context.Context, qname, qtype string) (cache.RRs, error) {
	return r.ResolveContext(ctx, qname, qtype)
}

// ResolveContext finds DNS records of type qtype for the domain qname using
// the supplied context. Requests may time out earlier if timeout is
// shorter than a deadline set in ctx.
// For nonexistent domains, it will return an NXDOMAIN error.
// Specify an empty string in qtype to receive any DNS records found
// (currently A, AAAA, NS, CNAME, SOA, and TXT).
func (r *Resolver) ResolveContext(ctx context.Context, qname, qtype string) (cache.RRs, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	return r.resolve(ctx, utils.ToLowerFQDN(qname), qtype, 0)
}

func (r *Resolver) resolve(ctx context.Context, qname, qtype string, depth int) (cache.RRs, error) {
	if depth++; depth > MaxRecursion {
		//logMaxRecursion(qname, qtype, depth)
		return nil, ErrMaxRecursion
	}
	rrs, err := r.cacheGet(ctx, qname, qtype)
	if err != nil {
		return nil, err
	}
	if len(rrs) > 0 {
		return rrs, nil
	}
	//logResolveStart(qname, qtype, depth)
	//start := time.Now()
	rrs, err = r.iterateParents(ctx, qname, qtype, depth)
	//logResolveEnd(qname, qtype, rrs, depth, start, err)
	return rrs, err
}

func (r *Resolver) iterateParents(ctx context.Context, qname, qtype string, depth int) (cache.RRs, error) {
	chanRRs := make(chan cache.RRs, MaxNameservers)
	chanErrs := make(chan error, MaxNameservers)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	for pname, ok := qname, true; ok; pname, ok = utils.GetParent(pname) {
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
		nrrs, err := r.resolve(ctx, pname, "NS", depth)
		if err == NXDOMAIN || err == ErrTimeout || err == context.DeadlineExceeded {
			return nil, err
		}
		if err != nil {
			continue
		}

		// Check cache for specific queries
		if len(nrrs) > 0 && qtype != "" {
			rrs, err := r.cacheGet(ctx, qname, qtype)
			if err != nil {
				return nil, err
			}
			if len(rrs) > 0 {
				return rrs, nil
			}
		}

		// Query all nameservers in parallel
		count := 0
		for i := 0; i < len(nrrs) && count < MaxNameservers; i++ {
			nrr := nrrs[i]
			if nrr.Type != "NS" {
				continue
			}

			go func(host string) {
				rrs, err := r.exchange(ctx, host, qname, qtype, depth)
				if err != nil {
					chanErrs <- err
				} else {
					chanRRs <- rrs
				}
			}(nrr.Value)

			count++
		}

		queried := count

		// Wait for answer, error, or cancellation
		for ; count > 0; count-- {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case rrs := <-chanRRs:
				// NOTE: should we keep this disabled? I don't see any good reason to include a NS for
				// an answer in a recursive resolver.
				/*
				for _, nrr := range nrrs {
					if nrr.Name == qname && nrr.Type == "NS" {
						rrs = append(rrs, nrr)
					}
				}
				*/
				ctx := context.WithoutCancel(ctx)
				cancel() // stop any other work here before recursing
				return r.resolveCNAMEs(ctx, qname, qtype, rrs, depth)
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
		if qtype == "NS" && queried > 0 {
			return nil, err
		}
	}

	return nil, ErrNoResponse
}

func (r *Resolver) exchange(ctx context.Context, host, qname, qtype string, depth int) (cache.RRs, error) {
	count := 0
	arrs, err := r.resolve(ctx, host, "A", depth)
	if err != nil {
		return nil, err
	}
	for _, arr := range arrs {
		// FIXME: support AAAA records?
		if arr.Type != "A" {
			continue
		}

		// Never query more than MaxIPs for any nameserver
		if count++; count > MaxIPs {
			return nil, ErrMaxIPs
		}

		rrs, err := r.exchangeIP(ctx, host, arr.Value, qname, qtype, depth)
		if err == nil || err == NXDOMAIN || err == ErrTimeout {
			return rrs, err
		}

		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}

	return nil, ErrNoARecords
}

var dialerDefault = &net.Dialer{}

func (r *Resolver) exchangeIP(ctx context.Context, host, ip, qname, qtype string, depth int) (cache.RRs, error) {
	dtype := dns.StringToType[qtype]
	if dtype == 0 {
		dtype = dns.TypeA
	}
	var qmsg dns.Msg
	qmsg.SetQuestion(qname, dtype)
	if r.edns {
		qmsg.SetEdns0(r.udpsize, r.dnssec)
	}
	qmsg.MsgHdr.RecursionDesired = false

	// Synchronously query this DNS server
	start := time.Now()
	//timeout := r.timeout // belt and suspenders, since ctx has a deadline from ResolveErr
	if dl, ok := ctx.Deadline(); ok {
		if start.After(dl.Add(-TypicalResponseTime)) { // bail if we can't finish in time (start is too close to deadline)
			return nil, ErrTimeout
		}
		//timeout = dl.Sub(start)
	}

	// lookup using the specified resolver client
	// this code is agnostic to which client is used 
	// ip should be WITHOUT port number, clients take care of this themselves
	// retransmission is implemented in the client
	flags := clients.QueryFlags{
		AD: qmsg.AuthenticatedData, 
		RD: false, // Recursion Desired
		DO: utils.GetDo(&qmsg), // DNSSEC OK
	}
	dst := clients.Destination{ Server: ip, TLSHostname: host } // TLSHostname is ignored in case of UDP/TCP
	rmsgs, err := r.client.Lookup(ctx, dst, qmsg.Question, flags)
	select {
	case <-ctx.Done(): // Finished too late
		//logCancellation(host, &qmsg, rmsg, depth, dur, client.Timeout)
		return nil, ctx.Err()
	default:
		//logExchange(host, &qmsg, rmsg, depth, dur, client.Timeout, err) // Log hostname instead of IP
	}
	if err != nil || len(rmsgs) == 0 {
		return nil, err
	}
	// only consider first message
	rmsg := rmsgs[0]
	r.logger.Debug(fmt.Sprintf("Received message from client: %s", rmsg.String()))

	// FIXME: cache NXDOMAIN responses responsibly
	if rmsg.Rcode == dns.RcodeNameError {
		var hasSOA bool
		if qtype == "NS" {
			for _, drr := range rmsg.Ns {
				rr, ok := cache.ConvertRR(drr, r.expire)
				if !ok {
					continue
				}
				if rr.Type == "SOA" {
					hasSOA = true
					break
				}
			}
		}
		if !hasSOA {
			r.cache.AddNX(qname)
			return nil, NXDOMAIN
		}
	} else if rmsg.Rcode != dns.RcodeSuccess {
		return nil, errors.New(dns.RcodeToString[rmsg.Rcode]) // FIXME: should (*Resolver).exchange special-case this error?
	}

	// Cache records returned
	rrs := r.saveDNSRR(host, qname, append(append(rmsg.Answer, rmsg.Ns...), rmsg.Extra...))

	// Resolve IP addresses of nameservers if the response didn't include glue records.
	// This handles out-of-bailiwick (OOB) referrals where the nameserver is outside the
	// queried domain's hierarchy (e.g., pnnl.gov using adns1.es.net as its NS).
	// In OOB cases, the parent zone's server cannot provide glue records, so we must
	// resolve the NS address separately. See https://github.com/domainr/dnsr/issues/174
	if qtype == "NS" {
		for _, rr := range rrs {
			if rr.Type != "NS" {
				continue
			}
			arrs, err := r.cacheGet(ctx, rr.Value, "A")
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
					r.cache.DeleteNX(rr.Value)
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

func (r *Resolver) resolveCNAMEs(ctx context.Context, qname, qtype string, crrs cache.RRs, depth int) (cache.RRs, error) {
	var rrs cache.RRs
	for _, crr := range crrs {
		rrs = append(rrs, crr)
		if crr.Type != "CNAME" || crr.Name != qname {
			continue
		}
		//logCNAME(crr.String(), depth)
		crrs, _ := r.resolve(ctx, crr.Value, qtype, depth)
		for _, rr := range crrs {
			r.cache.Add(qname, rr)
			rrs = append(rrs, rr)
		}
	}
	return rrs, nil
}

// saveDNSRR saves 1 or more DNS records to the resolver cache.
func (r *Resolver) saveDNSRR(host, qname string, drrs []dns.RR) cache.RRs {
	var rrs cache.RRs
	cl := dns.CountLabel(qname)
	for _, drr := range drrs {
		rr, ok := cache.ConvertRR(drr, r.expire)
		if !ok {
			continue
		}
		if dns.CountLabel(rr.Name) < cl && dns.CompareDomainName(qname, rr.Name) < 2 {
			// fmt.Fprintf(os.Stderr, "Warning: potential poisoning from %s: %s -> %s\n", host, qname, drr.String())
			continue
		}
		r.cache.Add(rr.Name, rr)
		if rr.Name != qname {
			continue
		}
		rrs = append(rrs, rr)
	}
	return rrs
}

// cacheGet returns a randomly ordered slice of DNS records.
func (r *Resolver) cacheGet(ctx context.Context, qname, qtype string) (cache.RRs, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	any := r.cache.Get(qname)
	if any == nil {
		any = r.rootcache.Get(qname)
	}
	if any == nil {
		return nil, nil
	}
	if len(any) == 0 {
		return nil, NXDOMAIN
	}
	rrs := make(cache.RRs, 0, len(any))
	for _, rr := range any {
		if qtype == "" || rr.Type == qtype {
			rrs = append(rrs, rr)
		}
	}
	if len(rrs) == 0 && (qtype != "" && qtype != "NS") {
		return nil, nil
	}
	return rrs, nil
}
