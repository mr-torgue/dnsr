package dnsr

import (
	"strings"

	_ "embed"

	"github.com/mr-torgue/dnsr/pkg/cache"
	"github.com/miekg/dns"
)

//go:generate curl -O https://www.internic.net/domain/named.root

//go:embed named.root
var root string

var rootCache *cache.Cache

func init() {
	rootCache = cache.NewCache(strings.Count(root, "\n"), false)
	zp := dns.NewZoneParser(strings.NewReader(root), "", "")

	for drr, ok := zp.Next(); ok; drr, ok = zp.Next() {
		rr, ok := cache.ConvertRR(drr, false)
		if ok {
			rootCache.Add(rr.Name, rr)
		}
	}

	if err := zp.Err(); err != nil {
		panic(err)
	}
}