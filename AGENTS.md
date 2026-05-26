# Short Description
This project contains an implementation for a DNS resolver that supports dnssec.
Written in GO.

# Rules
- always create a test case for code

# Project Structure
- `Archive` - can be ignored, contains old files
- `cmd` - contains interfaces for our software
- `internal` - please ignore
- `pkg` - contains our packages
-- `cache` - our cache implementation
-- `clients` - contains a set of different clients for sending DNS queries (quic, UDP, TCP, TLS)
-- `models` - contains data that has to be shared between packages
-- `utils` - contains utilities, such as loggers
- `resolver.go` - contains the code for our resolver
