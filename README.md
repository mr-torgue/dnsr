# dnsr

[![build status](https://img.shields.io/github/actions/workflow/status/domainr/dnsr/test.yaml.svg)](https://github.com/domainr/dnsr/actions)
[![go.dev reference](https://img.shields.io/badge/go.dev-reference-blue.svg?logo=go&logoColor=white)](https://pkg.go.dev/github.com/domainr/dnsr)

Iterative DNS resolver for [Go](https://golang.org/).

The `Resolve` method on `dnsr.Resolver` queries DNS for given name and type (`A`, `NS`, `CNAME`, etc.). The resolver caches responses for queries, and liberally (aggressively?) returns DNS records for a given name, not waiting for slow or broken name servers.

This code leans heavily on [Miek Gieben’s](https://github.com/miekg) excellent [DNS library](https://github.com/miekg/dns),
 and is currently in production use at [Domainr](https://domainr.com/).

## Changes
In anticipation of creating a resolver plugin for CoreDNS, we make a few changes to dnsr.
- [ ] Support sending queries over DoT and DoQ by using doggo to facilitate encryption between resolver and name server
- [ ] Let dnsr return the dns.Msg object directly
- [ ] Add support for UDP fragmentation

## Install

`go get github.com/domainr/dnsr`

## Usage

```go
package main

import (
  "fmt"
  "github.com/domainr/dnsr"
)

func main() {
  r := dnsr.NewResolver(dnsr.WithCache(10000))
  for _, rr := range r.Resolve("google.com", "TXT") {
    fmt.Println(rr.String())
  }
}
```

Or construct with `dnsr.NewResolver(dnsr.WithExpiry())` to expire cache entries based on TTL.

[Documentation](https://pkg.go.dev/github.com/domainr/dnsr)

## Development

Run `go generate` in Go 1.4+ to refresh the [root zone hint file](http://www.internic.net/domain/named.root). Pull requests welcome.

## Copyright

© nb.io, LLC
