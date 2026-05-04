package cache

import (
	"strings"
	"os"
	"fmt"

	"github.com/miekg/dns"
)

// LoadRootfile loads a rootfile and returns it as a cache.
// Does not do any semantic checks, so use with care!
func LoadRootfile(filename string) *Cache {
	content, err := os.ReadFile(filename)
	if err != nil {
		fmt.Printf("Error reading rootfile: %v\n", err)
		return nil
	}
	contentStr := string(content)
	rootCache := NewCache(strings.Count(contentStr, "\n"), false)
	zp := dns.NewZoneParser(strings.NewReader(contentStr), "", "")

	for drr, ok := zp.Next(); ok; drr, ok = zp.Next() {
		rr, ok := ConvertRR(drr, false)
		if ok {
			rootCache.Add(rr.Name, rr)
		}
	}

	if err := zp.Err(); err != nil {
		panic(err)
	}
	return rootCache
}