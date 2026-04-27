package utils

import (
	"testing"

  	"github.com/stretchr/testify/assert"
)

func TestToLowerFQDN(t *testing.T) {
	tests := []struct {
        name string
        domain string
		expected string
    }{
        {"Should return anything.com.", "ANYTHING.com", "anything.com."},
        {"Should return boo.net.", "boO.net", "boo.net."},
        {"Should return just.another.horse.", "just.another.HORSE", "just.another.horse."},
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
			name := ToLowerFQDN(tt.domain)
  			assert.Equal(t, tt.expected, name, tt.name)
        })
    }
}

func TestParent(t *testing.T) {
	tests := []struct {
        name string
        domain string
		expected string
		expectedSuccess bool
    }{
        {"Should return com.", "example.com", "com.", true},
        {"Should return com.", "EXAMPLE.cOm", "com.", true},
        {"Should return example.com.", "test.EXAMPLE.cOm", "example.com.", true},
        {"Should return .", "cOm", ".", true},
        {"Should return nothing", "", "", false},
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
			parent, res := GetParent(tt.domain)
  			assert.Equal(t, tt.expected, parent, tt.name)
  			assert.Equal(t, tt.expectedSuccess, res, "success should match")
        })
    }
}