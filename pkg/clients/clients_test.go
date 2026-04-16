package clients

import (
	"testing"
	"time"

	"github.com/nbio/st"
)

func TestNewClientConfig(t *testing.T) {
	config := NewClientConfig(nil, "udp", 23)
	st.Expect(t, config.logger, nil)
}