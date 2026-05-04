package cache

import (
	"sync"
	"testing"
	"time"

	"github.com/nbio/st"
)

func TestCache(t *testing.T) {
	c := NewCache(100, false)
	c.AddNX("hello.")
	rr := RR{Name: "hello.", Type: "A", Value: "1.2.3.4"}
	c.Add("hello.", rr)
	rrs := c.Get("hello.")
	st.Expect(t, len(rrs), 1)
}

func TestLiveCacheEntry(t *testing.T) {
	c := NewCache(100, true)
	c.AddNX("alive.")
	alive := time.Now().Add(time.Minute)
	rr := RR{Name: "alive.", Type: "A", Value: "1.2.3.4", Expiry: alive}
	c.Add("alive.", rr)
	rrs := c.Get("alive.")
	st.Expect(t, len(rrs), 1)
}

func TestContainsCacheEntry(t *testing.T) {
	c := NewCache(100, true)
	c.AddNX("alive.")
	alive := time.Now().Add(time.Minute)
	rr := RR{Name: "alive.", Type: "A", Value: "1.2.3.4", Expiry: alive}
	c.Add("alive.", rr)
	success := c.Contains("alive.")
	st.Expect(t, success, true)
}

func TestExpiredCacheEntry(t *testing.T) {
	c := NewCache(100, true)
	c.AddNX("expired.")
	expired := time.Now().Add(-time.Minute)
	rr := RR{Name: "expired.", Type: "A", Value: "1.2.3.4", Expiry: expired}
	c.Add("expired.", rr)
	rrs := c.Get("expired.")
	st.Expect(t, len(rrs), 0)
}

func TestCacheContention(t *testing.T) {
	k := "expired."
	c := NewCache(10, true)
	var wg sync.WaitGroup
	f := func() {
		rrs := c.Get(k)
		st.Expect(t, len(rrs), 0)
		c.AddNX(k)
		expired := time.Now().Add(-time.Minute)
		rr := RR{Name: k, Type: "A", Value: "1.2.3.4", Expiry: expired}
		c.Add(k, rr)
		wg.Done()
	}
	for range 1000 {
		wg.Add(1)
		go f()
	}
	wg.Wait()
}

func TestDeleteNX(t *testing.T) {
	c := NewCache(100, false)

	// Add NXDOMAIN entry
	c.AddNX("nonexistent.")
	rrs := c.Get("nonexistent.")
	st.Expect(t, len(rrs), 0) // NXDOMAIN returns empty slice

	// Delete the NXDOMAIN entry
	c.DeleteNX("nonexistent.")
	rrs = c.Get("nonexistent.")
	st.Expect(t, rrs, RRs(nil)) // Entry should be completely gone

	// Verify deleteNX doesn't affect non-NXDOMAIN entries
	rr := RR{Name: "exists.", Type: "A", Value: "1.2.3.4"}
	c.Add("exists.", rr)
	c.DeleteNX("exists.") // Should not delete because it's not an NX entry
	rrs = c.Get("exists.")
	st.Expect(t, len(rrs), 1) // Entry should still exist
}

func TestDeleteNXConcurrent(t *testing.T) {
	c := NewCache(100, false)
	var wg sync.WaitGroup

	for range 100 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.AddNX("concurrent.")
			c.DeleteNX("concurrent.")
		}()
	}
	wg.Wait()
}
