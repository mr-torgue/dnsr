package cache

import (
	"testing"
    "time"
	
  	"github.com/stretchr/testify/require"
  	"github.com/stretchr/testify/assert"
)

// Tests if the proper 
func TestNewClientConfig(t *testing.T) {

    tests := []struct {
        name            string
        filename        string
        expectedSuccess bool
        expectedRR      []RR
    }{
        {
            name:            "should parse correctly",
            filename:        "./testdata/named.root",
            expectedSuccess: true,
            expectedRR: []RR{
                {".", "NS", "A.ROOT-SERVERS.NET.", 3600000, time.Now()},
                {"a.root-servers.net.", "A", "198.41.0.4", 3600000, time.Now()},
                {"a.root-servers.net.", "AAAA", "2001:503:ba3e::2:30", 3600000, time.Now()},
            },
        },
        {
            name:            "should load custom values",
            filename:        "testdata/custom.root",
            expectedSuccess: true,
            expectedRR: []RR{
                {".", "NS", "IAMROOT.", 3600000, time.Now()},
                {"iamroot.", "A", "1.2.3.4", 3600000, time.Now()},
                {"iamroot.", "AAAA", "2001::30", 3600000, time.Now()},
            },
        },
        {
            name:            "should return panic",
            filename:        "testdata/wrong.root",
            expectedSuccess: false,
            expectedRR: nil,
        },
        {
            name:            "should return panic because of typo",
            filename:        "testdata/wrong2.root",
            expectedSuccess: false,
            expectedRR: nil,
        },
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
			if !tt.expectedSuccess {
				assert.Panics(t, func(){ LoadRootfile(tt.filename) })
			} else {
				c := LoadRootfile(tt.filename)
				require.NotNil(t, c, "rootcache should not be nil")
				for _, rr := range tt.expectedRR {
					rrs := c.Get(rr.Name)
					assert.NotNil(t, rrs, "results should not be nil")
					assert.NotEqual(t, rrs, EmptyRRs, "results should not be empty")
				}
			}
        })
    }
}