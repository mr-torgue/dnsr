package cache

// Base functionality copied from https://github.com/domainr/dnsr/blob/main/cache.go.
// The following changes have been made:
//   1. Uses the CoreDNS cache package: https://github.com/coredns/coredns/plugin/pkg/cache
//   2. Add support for both positive and negative caches
//   3. Caches items that align with the dns.Msg structure
//   4. Integrates the rootzone file 
//At the moment, it does not remove stale entries.
// FIXME should we clean the cache every now and then?
// TODO add support for exception lists as in the CoreDNS plugin

import (
	"time"
	"hash/fnv"
	"encoding/binary"
	"strings"
	"os"
	"log/slog"
	"fmt"

	"github.com/coredns/coredns/plugin/pkg/cache"
	"github.com/coredns/coredns/plugin/pkg/dnsutil"
	"github.com/coredns/coredns/plugin/pkg/response"
	"github.com/mr-torgue/dnsr/pkg/utils"
	"github.com/miekg/dns"
)

type Cache struct {
	logger  *slog.Logger
	expire  bool // if true, entries stay in the cache until space runs out
	ncache  *cache.Cache[*item]
	ncap    int
	nttl    time.Duration

	pcache  *cache.Cache[*item]
	pcap    int
	pttl    time.Duration

	rootcache map[uint64]*item
}

// Default values
const (
	DefaultExpire = false
	DefaultNcap = 1000
	DefaultNttl = 41800
	DefaultPcap = 1000
	DefaultPttl = 43600
)

// Cache options
type Option func(*Cache)

// WithLogger specifies a logger
func WithLogger(logger *slog.Logger) Option {
	return func(c *Cache) {
		// TODO should we add some more checks?
		c.logger = logger
	}
}

func WithExpire() Option {
	return func(c *Cache) {
		c.expire = true
	}
}

func WithNcap(ncap int) Option {
	return func(c *Cache) {
		c.ncap = ncap
	}
}

func WithNttl(nttl time.Duration) Option {
	return func(c *Cache) {
		c.nttl = nttl * time.Second
	}
}

func WithPcap(pcap int) Option {
	return func(c *Cache) {
		c.pcap = pcap
	}
}

func WithPttl(pttl time.Duration) Option {
	return func(c *Cache) {
		c.pttl = pttl * time.Second
	}
}

// loadRootfile loads a rootfile. We convert them to item (kind of like a dns.Msg).
// This way, we can load from the zone file the same way as loading from cache.
func loadRootfile(rootfile string) map[uint64]*item {
	root := make(map[uint64]*item)
	rootfileContent, err := os.ReadFile(rootfile)
	if err != nil {
		fmt.Printf("Error reading rootfile: %v\n", err)
		return nil
	}
	zp := dns.NewZoneParser(strings.NewReader(string(rootfileContent)), "", "")

	msgs := make(map[string]*dns.Msg)
	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		key := fmt.Sprintf("%s%d", dns.Name(rr.Header().Name).String(), rr.Header().Rrtype)
		if _, exists := msgs[key]; !exists {
			if rr.Header().Rrtype == 0 {
				return nil // this should not happen with well-formed files
			}
			msgs[key] = &dns.Msg{}
			msgs[key].SetQuestion(rr.Header().Name, rr.Header().Rrtype)
			msgs[key].MsgHdr.RecursionDesired = false
		}
		msgs[key].Answer = append(msgs[key].Answer, rr)
	}

	now := time.Now()
	for _, msg := range msgs {
		mt, _ := response.Typify(msg, now.UTC())
		valid, k := key(name(msg), msg, mt, do(msg), msg.CheckingDisabled)
		if valid {
			root[k] = newItem(msg, now, 0)
		}
	}
	return root
}

func WithRootzone(rootfile string) Option {
	return func(c *Cache) {
		c.rootcache = loadRootfile(rootfile)
	}
}

// NewCache initializes and returns a new cache instance.
// Cache capacity defaults to MinCacheCapacity if <= 0.
func NewCache(options ...Option) *Cache {
	// set default values
	c := &Cache{ 
		expire: DefaultExpire,
		ncap: DefaultNcap,
		nttl: DefaultNttl * time.Second,
		pcap: DefaultPcap,
		pttl: DefaultPttl * time.Second,
	}
	// parse options
	for _, o := range options {
		o(c)
	}
	// initialize caches	
	if c.logger == nil {
		c.logger = utils.InitLogger(false)
	}
	c.ncache = cache.New[*item](c.ncap)
	c.pcache = cache.New[*item](c.pcap)
	if c.rootcache == nil {
		c.rootcache = loadRootfile("named.root")
	}
	c.logger.Debug(fmt.Sprintf("Cache Config: %+v", c))
	return c
}

// Add adds a dns.Msg to the cache. Depending on the response code, it will
// be added to the negative or positive cache. Clean up strategy: when we 
// get notice that the cache is full, we do a full sweep to remove old data.
// By default uses time.Now().
func (c *Cache) Add(msg *dns.Msg) {
	c.AddWithTime(msg, time.Now())
}

func (c *Cache) AddWithTime(msg *dns.Msg, now time.Time) {
	mt, _ := response.Typify(msg, now.UTC())
	valid, k := key(name(msg), msg, mt, do(msg), msg.CheckingDisabled)
	if valid {
		c.logger.Debug(fmt.Sprintf("Adding msg %s with key %d", name(msg), k))
		c.add(msg, k, mt)
	} 
}

func (c *Cache) add(msg *dns.Msg, key uint64, mt response.Type) {
	// calculate the ttl 
	ttl := dnsutil.MinimalTTL(msg, mt)
	switch mt {
	case response.NoError, response.Delegation:
		i := newItem(msg, time.Now(), min(c.pttl, ttl)) 
		c.pcache.Add(key, i) 
	case response.NameError, response.NoData, response.ServerError:
		i := newItem(msg, time.Now(), min(c.nttl, ttl))
		c.ncache.Add(key, i) 
	case response.OtherError:
		// don't cache these
	default:
		c.logger.Debug(fmt.Sprintf("Caching called with unknown classification: %+v", mt))
	}
}


func (c *Cache) Get(msg *dns.Msg) *dns.Msg {
	return c.GetWithTime(msg, time.Now().UTC())
}

// Get retrieves the msg from the ncache or pcache.
func (c *Cache) GetWithTime(msg *dns.Msg, now time.Time) *dns.Msg {
	qname := name(msg)
	qtype := qtype(msg)
	do := do(msg)
	key := hash(qname, qtype, do, msg.CheckingDisabled)
	c.logger.Debug(fmt.Sprintf("Getting msg %s with key %d", qname, key))
	if i, ok := c.ncache.Get(key); ok {
		ttl := i.ttl(now)
		if i.matches(qname, qtype) && (ttl > 0 || !c.expire) {
			return i.toMsg(msg, now, do, msg.AuthenticatedData)
		}
		if c.expire && ttl <= 0 {
			c.ncache.Remove(key)
		}
	}
	if i, ok := c.pcache.Get(key); ok {
		ttl := i.ttl(now)
		if i.matches(qname, qtype) && (ttl > 0 || !c.expire) {
			c.logger.Debug("return")
			return i.toMsg(msg, now, do, msg.AuthenticatedData)
		}
		if c.expire && ttl <= 0 {
			c.pcache.Remove(key)
		}
	}
	if i, ok := c.rootcache[key]; ok {
		return i.toMsg(msg, now, do, msg.AuthenticatedData)
	}
	return nil
}

func (c *Cache) Delete(msg *dns.Msg) {
	qname := name(msg)
	qtype := qtype(msg)
	do := do(msg)
	key := hash(qname, qtype, do, msg.CheckingDisabled)
	c.ncache.Remove(key)
	c.pcache.Remove(key)
}

// helpers
var one = []byte("1")
var zero = []byte("0")

func hash(qname string, qtype uint16, do, cd bool) uint64 {
	h := fnv.New64()

	if do {
		h.Write(one)
	} else {
		h.Write(zero)
	}

	if cd {
		h.Write(one)
	} else {
		h.Write(zero)
	}

	var qtypeBytes [2]byte
	binary.BigEndian.PutUint16(qtypeBytes[:], qtype)
	h.Write(qtypeBytes[:])
	h.Write([]byte(qname))
	return h.Sum64()
}

// key returns key under which we store the item, -1 will be returned if we don't store the message.
// Currently we do not cache Truncated, errors zone transfers or dynamic update messages.
// qname holds the already lowercased qname.
func key(qname string, m *dns.Msg, t response.Type, do, cd bool) (bool, uint64) {
	// We don't store truncated responses.
	if m.Truncated {
		return false, 0
	}
	// Nor errors or Meta or Update.
	if t == response.OtherError || t == response.Meta || t == response.Update {
		return false, 0
	}

	return true, hash(qname, m.Question[0].Qtype, do, cd)
}

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