package dnsr

import (
	"context"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/mr-torgue/dnsr/pkg/utils"
)

// validateDNSSEC does the DNSSEC validation.
func (r *Resolver) validateDNSSEC(ctx context.Context, msg *dns.Msg, records []dns.RR, sigs []dns.RR) ValidationStatus {
	if len(records) == 0 {
		return Indeterminate
	}

	//name := records[0].Header().Name

	// if no signatures, check if the zone is legally unsigned (Insecure)
	if len(sigs) == 0 {
		//enable later
		//_, status := r.getValidatedDS(ctx, name)
		return Insecure
	}

	// get the Signer's Name from the RRSIG
	signerName := sigs[0].(*dns.RRSIG).SignerName

	// fetch and validate the DNSKEYs for this zone
	keys, status := r.getValidatedDNSKEYs(ctx, signerName)
	if status != Secure {
		return status
	}

	// verify the RRSet with the validated keys
	if r.verifyRRSet(ctx, records, sigs, keys) {
		return Secure
	}

	return Bogus
}

// getValidatedDNSKEYs returns DNSKEY RRs.
// Tests if the ZSKs are signed by the KSKs.
// Returns only the ZSKs.
func (r *Resolver) getValidatedDNSKEYs(ctx context.Context, zone string) ([]dns.RR, ValidationStatus) {
	// try to load from cache first
	keyMsg, status, ok := r.Load(zone, dns.TypeDNSKEY, true)
	if ok && status == Secure {
		return keyMsg.Answer, Secure
	}

	// use cd=true to avoid infinite validation loops during the fetch
	keyMsg, err := r.resolve(ctx, zone, dns.TypeDNSKEY, 0, true)
	if err != nil || len(keyMsg.Answer) == 0 {
		r.logger.Debug("[DNSSEC] Could not resolve DNSKEY")
		return nil, Bogus
	}

	// separate DNSKEYs and their RRSIGs
	var zsk, ksk, sigs []dns.RR
	for _, rr := range keyMsg.Answer {
		if rr.Header().Rrtype == dns.TypeDNSKEY {
			key := rr.(*dns.DNSKEY)
			switch key.Flags {
			case 257:
				ksk = append(ksk, key)
			case 256:
				zsk = append(zsk, key)
			}
		} else if rr.Header().Rrtype == dns.TypeRRSIG {
			sigs = append(sigs, rr)
		}
	}

	// to trust these keys, we need the DS record from the parent
	dsRecords, dsStatus := r.getValidatedDS(ctx, zone)
	if dsStatus != Secure {
		return nil, dsStatus
	}

	// only use KSKs that have a proper chain
	var validksk []dns.RR
	for _, dsRR := range dsRecords {
		ds := dsRR.(*dns.DS)
		for _, keyRR := range ksk {
			key := keyRR.(*dns.DNSKEY)
			if strings.EqualFold(key.ToDS(ds.DigestType).Digest, ds.Digest) {
				validksk = append(validksk, key)
			}
		}
	}

	// return Bogus if no valid keys have been found
	if len(validksk) == 0 {
		r.logger.Debug("[DNSSEC] Could not find valid KSKs")
		return nil, Bogus
	}

	// the DNSKEY RRSet must be self-signed (ZSK signed by KSK)
	if r.verifyRRSet(ctx, append(zsk, ksk...), sigs, ksk) {
		return zsk, Secure
	}

	return nil, Bogus
}

func (r *Resolver) getValidatedDS(ctx context.Context, zone string) ([]dns.RR, ValidationStatus) {
	parent, _ := utils.GetParent(zone)

	// try to load from cache first
	dsMsg, status, ok := r.Load(zone, dns.TypeDS, true)
	if ok && status == Secure {
		return dsMsg.Answer, Secure
	}

	// Fetch DS record from parent
	dsMsg, err := r.resolve(ctx, zone, dns.TypeDS, 0, true)
	if err != nil {
		return nil, Indeterminate
	}

	// If DS exists in Answer section
	if len(dsMsg.Answer) > 0 {
		var dsRecords, sigs []dns.RR
		for _, rr := range dsMsg.Answer {
			if rr.Header().Rrtype == dns.TypeDS {
				dsRecords = append(dsRecords, rr)
			} else if rr.Header().Rrtype == dns.TypeRRSIG {
				sigs = append(sigs, rr)
			}
		}

		// Validate the DS RRSet using parent's DNSKEYs
		parentKeys, parentStatus := r.getValidatedDNSKEYs(ctx, parent)
		if parentStatus != Secure {
			return nil, parentStatus
		}

		if r.verifyRRSet(ctx, dsRecords, sigs, parentKeys) {
			return dsRecords, Secure
		}
		return nil, Bogus
	}

	// If DS is missing, look for NSEC/NSEC3 in Authority section to prove it's Insecure
	if r.verifyDenial(ctx, dsMsg, zone) {
		return nil, Insecure
	}

	return nil, Bogus
}

// Verify RRSet verifies the records.
func (r *Resolver) verifyRRSet(ctx context.Context, records []dns.RR, sigs []dns.RR, keys []dns.RR) bool {
	if len(sigs) == 0 || len(keys) == 0 || len(records) == 0 {
		return false
	}

	now := time.Now()

	for _, sigRR := range sigs {

		sig := sigRR.(*dns.RRSIG)
		if sig.ValidityPeriod(now) {
			return false
		}

		// note: returns true if at least one key matches.
		for _, keyRR := range keys {
			key := keyRR.(*dns.DNSKEY)
			if key.KeyTag() == sig.KeyTag && key.Algorithm == sig.Algorithm {
				if sig.Verify(key, records) == nil {
					return true
				}
			}
		}
	}
	return false
}

func (r *Resolver) verifyDenial(ctx context.Context, msg *dns.Msg, qname string) bool {
	// A robust NSEC3 proof is very complex.
	// At a basic level, we check if there are NSEC/NSEC3 records
	// and if they are signed by the parent.

	parent, _ := utils.GetParent(qname)
	parentKeys, status := r.getValidatedDNSKEYs(ctx, parent)
	if status != Secure {
		return false
	}

	foundProof := false
	for _, rr := range msg.Ns {
		if rr.Header().Rrtype == dns.TypeNSEC || rr.Header().Rrtype == dns.TypeNSEC3 {
			// Find the RRSIG for this NSEC/NSEC3 record in the same section
			var nsecSigs []dns.RR
			for _, sigRR := range msg.Ns {
				if s, ok := sigRR.(*dns.RRSIG); ok && s.TypeCovered == rr.Header().Rrtype {
					nsecSigs = append(nsecSigs, s)
				}
			}

			if r.verifyRRSet(ctx, []dns.RR{rr}, nsecSigs, parentKeys) {
				// Note: In a production resolver, you must also verify that
				// the NSEC/NSEC3 range actually covers the qname or the DS type.
				foundProof = true
			}
		}
	}

	return foundProof
}
