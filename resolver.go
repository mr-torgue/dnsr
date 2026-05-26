package dnsr

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/coredns/coredns/plugin/pkg/cache"
	"github.com/miekg/dns"
	"github.com/mr-torgue/dnsr/pkg/clients"
	"github.com/mr-torgue/dnsr/pkg/utils"
)

// DNS Resolution configuration.
var (
	Timeout               = 10 * time.Second
	ClientTimeout         = 2 * time.Second
	TypicalResponseTime   = 100 * time.Millisecond
	MaxRecursion          = 10
	MaxNameservers        = 2
	MaxIPs                = 2
	DefaultClientType     = "udp"
	DefaultCapacity       = 20000
	DefaultTCPRetry       = true
	DefaultClassicRetry   = true
	DefaultDNSSEC         = false
	DefaultEDNS           = false
	DefaultUDPSize        = uint16(1232)
	DefaultRootfile       = "named.root"
	DefaultRootanchorfile = "root-anchors.xml"
)

// Resolver errors.
var (
	NXDOMAIN = fmt.Errorf("NXDOMAIN")

	ErrMaxRecursion = fmt.Errorf("maximum recursion depth reached: %d", MaxRecursion)
	ErrMaxIPs       = fmt.Errorf("maximum name server IPs queried: %d", MaxIPs)
	ErrNoARecords   = fmt.Errorf("no A records found for name server")
	ErrNoResponse   = fmt.Errorf("no responses received")
	ErrTimeout      = fmt.Errorf("timeout expired") // TODO: Timeouter interface? e.g. func (e) Timeout() bool { return true }
	ErrNoCache      = fmt.Errorf("could not initialize cache")
	ErrNoRootmap    = fmt.Errorf("could not initialize rootmap")
	ErrNoClient     = fmt.Errorf("could not initialize client")
	ErrNonTLD       = fmt.Errorf("non-TLD query at root")
)

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

// WithRootmap specifies the storage for RR for the root domain.
func WithRootmap(filename string, anchorfilename string, dnssec bool) Option {
	return func(r *Resolver) {
		r.rootmap = LoadRootmap(filename, anchorfilename, dnssec)
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
func WithClassicRetry(classicRetry bool) Option {
	return func(r *Resolver) {
		r.classicRetry = classicRetry
	}
}

// WithDNSSEC specifies that DNSSEC validation should be used.
func WithDNSSEC(dnssec bool) Option {
	return func(r *Resolver) {
		r.dnssec = dnssec
		// enable EDNS
		if dnssec {
			r.edns = true
		}
	}
}

// WithEDNS specifies that EDNS is enabledd.
func WithEDNS(edns bool) Option {
	return func(r *Resolver) {
		r.edns = edns
		if !r.edns && r.dnssec {
			panic("EDNS should be enabled for DNSSEC")
		}
	}
}

// WithUDPSize specifies the EDNS UDP size.
func WithUDPSize(udpsize uint16) Option {
	return func(r *Resolver) {
		r.udpsize = udpsize
	}
}

// Resolver implements a primitive, non-recursive, caching DNS resolver.
type Resolver struct {
	logger  *slog.Logger
	timeout time.Duration
	// cache settings
	cache    *cache.Cache[*Entry]
	capacity int
	rootmap  map[uint64]([]dns.RR) // contains rootzone information
	// client settings
	client        clients.Client // supported: udp, tcp, doh, doq, tls, and dnscrypt
	clientType    string
	clientTimeout time.Duration
	tcpRetry      bool // indicates if queries should be retried when the client fails
	classicRetry  bool
	dnssec        bool // turn on/off dnssec validation
	edns          bool
	udpsize       uint16
}

// NewResolver returns an initialized Resolver with options.
// By default, the returned Resolver will have cache capacity 0
// and the default network timeout (Timeout).
func NewResolver(options ...Option) *Resolver {
	// set default values
	r := &Resolver{
		timeout:       Timeout,
		capacity:      DefaultCapacity,
		clientType:    DefaultClientType,
		clientTimeout: ClientTimeout,
		tcpRetry:      DefaultTCPRetry,
		classicRetry:  DefaultClassicRetry,
		dnssec:        DefaultDNSSEC,
		edns:          DefaultEDNS,
		udpsize:       DefaultUDPSize,
	}
	// parse options
	for _, o := range options {
		o(r)
	}
	// initialize complex structures
	if r.logger == nil {
		r.logger = utils.InitLogger(false)
	}
	r.cache = cache.New[*Entry](r.capacity)
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
	if r.rootmap == nil {
		r.rootmap = LoadRootmap(DefaultRootfile, DefaultRootanchorfile, r.dnssec)
		if r.rootmap == nil {
			panic(ErrNoRootmap)
		}
	}
	r.logger.Debug(fmt.Sprintf("Resolver Config: %+v", r))
	return r
}

// Resolve calls ResolveErr to find DNS records of type qtype for the domain qname.
// For nonexistent domains (NXDOMAIN), it will return an empty, non-nil slice.
// The boolean do indicates if DNSSEC is required.
func (r *Resolver) Resolve(qname string, qtype uint16, do bool, cd bool) *dns.Msg {
	rmsg, err := r.ResolveErr(qname, qtype, cd)
	if err != nil {
		r.logger.Debug(fmt.Sprintf("Resolver error: %v", err))
	}
	return rmsg
}

// ResolveErr finds DNS records of type qtype for the domain qname.
// For nonexistent domains, it will return an NXDOMAIN error.
// Specify an empty string in qtype to receive any DNS records found
// (currently A, AAAA, NS, CNAME, SOA, and TXT).
func (r *Resolver) ResolveErr(qname string, qtype uint16, cd bool) (*dns.Msg, error) {
	ctx, cancel := context.WithTimeout(context.Background(), r.timeout)
	defer cancel()
	return r.resolve(ctx, utils.ToLowerFQDN(qname), qtype, 0, cd)
}

// ResolveMsg returns a dns.Msg instead of a RRs. Basically, just wraps
// around r.resolve and converts the outcome to a dns.Msg.
func (r *Resolver) ResolveMsg(qmsg *dns.Msg) *dns.Msg {
	if qmsg != nil {
		qname := utils.GetName(qmsg)
		qtype := utils.GetType(qmsg)
		do := utils.GetDo(qmsg)
		cd := qmsg.MsgHdr.CheckingDisabled
		return r.Resolve(qname, qtype, do, cd)

	}
	return nil
}

// ResolveContext finds DNS records of type qtype for the domain qname using
// the supplied context. Requests may time out earlier if timeout is
// shorter than a deadline set in ctx.
// For nonexistent domains, it will return an NXDOMAIN error.
// Specify an empty string in qtype to receive any DNS records found
// (currently A, AAAA, NS, CNAME, SOA, and TXT).
// TODO(mrtorgue): add support for DNSSEC
// BUG(mrtorgue): add support for DNSSEC
func (r *Resolver) ResolveContext(ctx context.Context, qname string, qtype uint16, cd bool) (*dns.Msg, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	return r.resolve(ctx, utils.ToLowerFQDN(qname), qtype, 0, cd)
}

// resolve resolves a given query.
// TODO(mr-torgue): add support for DNSSEC
// BUG(mr-torgue): add support for DNSSEC
func (r *Resolver) resolve(ctx context.Context, qname string, qtype uint16, depth int, cd bool) (*dns.Msg, error) {
	if depth++; depth > MaxRecursion {
		//logMaxRecursion(qname, qtype, depth)
		return utils.CreateErrorResponse(qname, qtype, dns.RcodeServerFailure), ErrMaxRecursion
	}
	rmsg, status, ok := r.Load(qname, qtype, cd)
	// return if we have a cache answer (Insecure means we know no DNSSEC record exists)
	if ok && (status == Secure || status == Insecure) {
		return rmsg, nil
	}
	rmsg, err := r.iterateParents(ctx, qname, qtype, depth, cd)
	return rmsg, err
}

func (r *Resolver) iterateParents(ctx context.Context, qname string, qtype uint16, depth int, cd bool) (*dns.Msg, error) {
	chanRRs := make(chan *dns.Msg, MaxNameservers)
	chanErrs := make(chan error, MaxNameservers)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	for pname, ok := qname, true; ok; pname, ok = utils.GetParent(pname) {
		// If we’re looking for [foo.com,NS], then move on to the parent ([com,NS])

		if pname == qname && qtype == dns.TypeNS {
			continue
		}

		// Only query TLDs against the root nameservers
		if pname == "." && dns.CountLabel(qname) != 1 {
			// fmt.Fprintf(os.Stderr, "Warning: non-TLD query at root: dig +norecurse %s %s\n", qname, qtype)
			return utils.CreateErrorResponse(qname, qtype, dns.RcodeServerFailure), nil
		}

		// Get nameservers
		nrmsg, err := r.resolve(ctx, pname, dns.TypeNS, depth, true)
		if err == NXDOMAIN || err == ErrTimeout || err == context.DeadlineExceeded {
			return utils.CreateErrorResponse(qname, qtype, dns.RcodeServerFailure), err
		}
		if err != nil {
			continue
		}

		// check if previous query loaded the result in cache (glue records)
		if len(nrmsg.Answer) > 0 {
			rmsg, status, ok := r.Load(qname, qtype, cd)
			// return cached if exists
			if ok && (status == Secure || status == Insecure) && len(rmsg.Answer) > 0 {
				return rmsg, nil
			}
			if ok {
				return rmsg, fmt.Errorf("error")
			}
		}

		// Query all nameservers in parallel
		count := 0
		r.logger.Debug(fmt.Sprintf("found %d nameservers in Answer, found %d nameservers in Auth", len(nrmsg.Answer), len(nrmsg.Ns)))
		nrrs := append(nrmsg.Answer, nrmsg.Ns...)
		for i := 0; i < len(nrrs) && count < MaxNameservers; i++ {
			nrr := nrrs[i]
			if nrr.Header().Rrtype != dns.TypeNS {
				continue
			}

			go func(host string) {
				rmsg, err := r.exchange(ctx, host, qname, qtype, depth, cd)
				if err != nil {
					chanErrs <- err
				} else {
					chanRRs <- rmsg
				}
			}(utils.GetValue(nrr))

			count++
		}

		queried := count

		// Wait for answer, error, or cancellation
		for ; count > 0; count-- {
			select {
			case <-ctx.Done():
				return utils.CreateErrorResponse(qname, qtype, dns.RcodeServerFailure), ctx.Err()
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
					return utils.CreateErrorResponse(qname, qtype, dns.RcodeNameError), err
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
			return utils.CreateErrorResponse(qname, qtype, dns.RcodeServerFailure), err
		}
	}

	return utils.CreateErrorResponse(qname, qtype, dns.RcodeServerFailure), ErrNoResponse
}

// exchange looks up the IP address for the host (NS).
func (r *Resolver) exchange(ctx context.Context, host, qname string, qtype uint16, depth int, cd bool) (*dns.Msg, error) {
	count := 0
	armsg, err := r.resolve(ctx, host, dns.TypeA, depth, cd)
	if armsg.Rcode != dns.RcodeSuccess {
		return armsg, err
	}
	for _, arr := range armsg.Answer {
		// FIXME: support AAAA records?
		if arr.Header().Rrtype != dns.TypeA {
			continue
		}

		// Never query more than MaxIPs for any nameserver
		if count++; count > MaxIPs {
			armsg.Rcode = dns.RcodeServerFailure
			return armsg, ErrMaxIPs
		}

		rmsg, err := r.exchangeIP(ctx, host, utils.GetValue(arr), qname, qtype, depth, cd)
		if err == nil || err == NXDOMAIN || err == ErrTimeout {
			return rmsg, err
		}

		if ctx.Err() != nil {
			armsg.Rcode = dns.RcodeServerFailure
			return armsg, ctx.Err()
		}
	}

	armsg.Rcode = dns.RcodeServerFailure
	return armsg, ErrNoARecords
}

// exchangeIP directly connects to host on ip and tries to get an answer for qname:qtype.
func (r *Resolver) exchangeIP(ctx context.Context, host, ip, qname string, qtype uint16, depth int, cd bool) (*dns.Msg, error) {
	var qmsg dns.Msg
	var rmsg = new(dns.Msg)
	qmsg.SetQuestion(qname, qtype)
	if r.edns {
		qmsg.SetEdns0(r.udpsize, r.dnssec)
	}
	qmsg.MsgHdr.RecursionDesired = false
	rmsg.SetReply(&qmsg)

	// Synchronously query this DNS server
	start := time.Now()
	if dl, ok := ctx.Deadline(); ok {
		if start.After(dl.Add(-TypicalResponseTime)) { // bail if we can't finish in time (start is too close to deadline)
			rmsg.Rcode = dns.RcodeServerFailure
			return rmsg, ErrTimeout
		}
	}

	// lookup using the specified resolver client
	// this code is agnostic to which client is used
	// ip should be WITHOUT port number, clients take care of this themselves
	// retransmission is implemented in the client
	flags := clients.QueryFlags{
		AD: false,    // NOTE: I think this is correct, but verify
		RD: false,    // Recursion Desired
		DO: r.dnssec, // DNSSEC OK
		CD: true,
	}
	dst := clients.Destination{Server: ip, TLSHostname: host} // TLSHostname is ignored in case of UDP/TCP
	rmsgs, err := r.client.Lookup(ctx, dst, qmsg.Question, flags)
	select {
	case <-ctx.Done(): // Finished too late
		rmsg.Rcode = dns.RcodeServerFailure
		return rmsg, ctx.Err()
	default:
		//logExchange(host, &qmsg, rmsg, depth, dur, client.Timeout, err) // Log hostname instead of IP
	}
	if err != nil || len(rmsgs) == 0 {
		rmsg.Rcode = dns.RcodeServerFailure
		return rmsg, err
	}
	// only consider first message
	rmsg = rmsgs[0]
	r.logger.Debug(fmt.Sprintf("Received message from client for query (%s, %s): %s", qname, dns.TypeToString[qtype], rmsg.String()))

	// FIXME: cache NXDOMAIN responses responsibly
	if rmsg.Rcode == dns.RcodeNameError {
		var hasSOA bool
		if qtype == dns.TypeNS {
			for _, rr := range rmsg.Ns {
				if rr.Header().Rrtype == dns.TypeSOA {
					hasSOA = true
					break
				}
			}
		}
		if !hasSOA {
			r.Save(ctx, rmsg, cd)
			return rmsg, NXDOMAIN
		}
	} else if rmsg.Rcode != dns.RcodeSuccess {
		return rmsg, errors.New(dns.RcodeToString[rmsg.Rcode])
	}

	// Cache records returned
	status := r.Save(ctx, rmsg, cd)
	r.logger.Debug(fmt.Sprintf("Message saved with status: %v", status))

	// Resolve IP addresses of nameservers if the response didn't include glue records.
	// This handles out-of-bailiwick (OOB) referrals where the nameserver is outside the
	// queried domain's hierarchy (e.g., pnnl.gov using adns1.es.net as its NS).
	// In OOB cases, the parent zone's server cannot provide glue records, so we must
	// resolve the NS address separately. See https://github.com/domainr/dnsr/issues/174
	if qtype == dns.TypeNS {
		// CHECK IF CORRECT
		//for _, rr := range rrs {
		rrs := append(append(rmsg.Answer, rmsg.Ns...), rmsg.Extra...)
		//rrs := rmsg.Answer
		for _, rr := range rrs {
			if rr.Header().Rrtype != dns.TypeNS {
				continue
			}
			val := utils.GetValue(rr)
			armsg, _, ok := r.Load(val, dns.TypeA, cd)
			if ok && armsg.Rcode == dns.RcodeNameError {
				continue
			}
			// bad cache hit or bogus entry
			//	if ok && (status == Bogus || status == Indeterminate) {
			//		break
			//}
			if len(armsg.Answer) == 0 {
				// Try asking the current nameserver for the NS's A record (fast path).
				// This works when glue records are available or the NS is in-bailiwick.
				armsg, err := r.exchangeIP(ctx, host, ip, val, dns.TypeA, depth+1, cd)
				if armsg.Rcode == dns.RcodeNameError {
					// The nameserver returned NXDOMAIN, which likely means out-of-bailiwick
					// (e.g., asking a .gov server for a .net address). This NXDOMAIN is
					// not authoritative, so remove it from cache and resolve from root instead.
					r.cache.Remove(Key(val, dns.TypeA))

					armsg, err = r.resolve(ctx, val, dns.TypeA, depth+1, false)
					if armsg.Rcode == dns.RcodeNameError {
						// NS truly doesn't exist, try the next nameserver
						continue
					}
				}
				if err != nil {
					// On timeout or other transient errors, try the next nameserver
					continue
				}
			}
			rmsg.Answer = append(rmsg.Answer, armsg.Answer...)
		}
	}

	// assume rmsg.Rcode == dns.RcodeSuccess
	return rmsg, nil
}

// resolveCNAMEs checks if an RR is a CNAME and resolves them.
func (r *Resolver) resolveCNAMEs(ctx context.Context, qname string, qtype uint16, rmsg *dns.Msg, depth int) (*dns.Msg, error) {

	rmsg.Answer, _ = r.resolveCNAMEsSection(ctx, qname, qtype, rmsg.Answer, depth)
	rmsg.Ns, _ = r.resolveCNAMEsSection(ctx, qname, qtype, rmsg.Ns, depth)
	rmsg.Extra, _ = r.resolveCNAMEsSection(ctx, qname, qtype, rmsg.Extra, depth)
	return rmsg, nil
}

// resolveCNAMEsSection resolves the CNAMEs for a given section
func (r *Resolver) resolveCNAMEsSection(ctx context.Context, qname string, qtype uint16, crrs []dns.RR, depth int) ([]dns.RR, error) {

	cnames := []dns.RR{}
	rrMap := make(map[uint64][]dns.RR)
	rrs := crrs

	// find all CNAME's
	for _, crr := range crrs {
		h := crr.Header()
		if h.Rrtype == dns.TypeCNAME {
			cnames = append(cnames, crr)
		} else if h.Rrtype == qtype {
			rrMap[Key(h.Name, h.Rrtype)] = append(rrMap[Key(h.Name, h.Rrtype)], crr)
		}
	}

	// for each cname, try to find it locally, else resolve
	for _, cname := range cnames {
		val := utils.GetValue(cname)
		// only resolve if not already found
		if _, exists := rrMap[Key(val, qtype)]; !exists {
			crmsg, _ := r.resolve(ctx, val, qtype, depth, false)
			rrs = append(rrs, crmsg.Answer...)
		}
	}
	return rrs, nil
}

// Save groups records into RRSets and caches them.
// cd=false triggers the DNSSEC verification process, iff r.dnssec=true.
func (r *Resolver) Save(ctx context.Context, msg *dns.Msg, cd bool) (status ValidationStatus) {
	if msg == nil {
		return Indeterminate
	}

	// Group records by RRSet (Name + Type)
	// We combine Answer, Ns, and Extra sections
	allRRs := append(append(msg.Answer, msg.Ns...), msg.Extra...)
	rrsets := make(map[uint64][]dns.RR)
	sigs := make(map[uint64][]dns.RR)

	for _, rr := range allRRs {
		h := rr.Header()
		if h.Rrtype == dns.TypeRRSIG {
			sig := rr.(*dns.RRSIG)
			k := Key(h.Name, sig.TypeCovered)
			sigs[k] = append(sigs[k], rr)
		} else if h.Rrtype == dns.TypeOPT || h.Rrtype == dns.TypeTSIG || h.Rrtype == dns.TypeIXFR || h.Rrtype == dns.TypeAXFR || h.Rrtype == dns.TypeMAILB || h.Rrtype == dns.TypeMAILA || h.Rrtype == dns.TypeANY {
			// ignore these RR's
			continue
		} else {
			k := Key(h.Name, h.Rrtype)
			rrsets[k] = append(rrsets[k], rr)
		}
	}

	// Cache each RRSet
	for k, records := range rrsets {

		// Determine Security Status
		status = Indeterminate
		if r.dnssec && !cd {
			status = r.validateDNSSEC(ctx, msg, records, sigs[k])
		} else if !r.dnssec {
			status = Insecure
		}

		h := records[0].Header()
		entry := &Entry{
			Name:    h.Name,
			Type:    h.Rrtype,
			Status:  status,
			Records: records,
			TTL:     h.Ttl,
			Expires: time.Now().Add(time.Duration(h.Ttl) * time.Second),
		}

		// set the sigs if dnssec is enabled and if they exist
		if r.dnssec {
			entry.Signatures = sigs[k]
		}

		// Adjust expiry based on RRSIG expiration if Secure
		if status == Secure {
			for _, s := range sigs[k] {
				sig := s.(*dns.RRSIG)
				exp := time.Unix(int64(sig.Expiration), 0)
				if exp.Before(entry.Expires) {
					entry.Expires = exp
				}
			}
		}

		r.logger.Debug(fmt.Sprintf("Adding entry to cache: %s:%s", entry.Name, dns.TypeToString[entry.Type]))
		r.cache.Add(k, entry)
	}

	return status
}

// Load retrieves an entry from cache.
// It handles the CD (Checking Disabled) logic.
func (r *Resolver) Load(qname string, qtype uint16, clientCD bool) (*dns.Msg, ValidationStatus, bool) {
	// always return a message
	msg := new(dns.Msg)
	msg.Rcode = dns.RcodeServerFailure

	key := Key(qname, qtype)
	// check rootmap first
	rootval := r.rootmap[key]
	if rootval != nil {
		msg.Answer = rootval
		msg.Rcode = dns.RcodeSuccess
		return msg, Secure, true
	}

	val, ok := r.cache.Get(key)
	if val == nil || !ok {
		r.logger.Debug(fmt.Sprintf("Cache entry not found: %s:%s", qname, dns.TypeToString[qtype]))
		return msg, Indeterminate, false
	}

	if time.Now().After(val.Expires) {
		r.logger.Debug(fmt.Sprintf("Cache entry expired: %s:%s", qname, dns.TypeToString[qtype]))
		r.cache.Remove(key)
		return msg, Indeterminate, false
	}

	// DNSSEC Status Check (Scenario logic)
	// 1. If Bogus and CD=0, return SERVFAIL (represented as nil here)
	if val.Status == Bogus && !clientCD {
		r.logger.Debug("Ignoring Bogus cache entry as CD=0")
		return msg, Bogus, true
	}
	// Construct response message
	msg.Answer = append(val.Records, val.Signatures...)
	msg.Rcode = val.Rcode

	// Set AD bit if Secure
	if val.Status == Secure {
		msg.AuthenticatedData = true
	}
	return msg, val.Status, true
}
