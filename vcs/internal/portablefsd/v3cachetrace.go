package portablefsd

import "github.com/steerlabs/portablefs/vcs/bench/lantrace"

// One decision names exactly one answer source, even if an entry absence and
// completeness could both rescue the same request. No attribution history is
// retained per filename. Coordinate describes existing bounded cache state.
func (d *v3DataPlane) cacheDecisionLocked(metric int, item *v3ItemRecord, name string, result v3CacheResult) lantrace.Event {
	e := lantrace.Event{Kind: lantrace.KindCache, Phase: lantrace.PhaseCandidate,
		Candidate: lantrace.CandidateAttrCache, CacheResult: lantrace.CacheMiss,
		Cert: lantrace.CertAbsent, Search: lantrace.SearchUnknown,
		Proof: lantrace.ProofValid, SourceState: lantrace.SourceNone,
		Coordinate: lantrace.CoordinateFirst}
	if metric == 0 {
		e.Item = item.item.ItemID
		if item.valid {
			e.Coordinate = lantrace.CoordinateRepeated
		}
	} else {
		e.Parent = item.item.ItemID
		e.NameHex, _ = lantrace.EncodeName([]byte(name))
		e.Candidate = lantrace.CandidateEntryCache
		_, negative := item.negatives[name]
		if item.children[name] != nil || negative {
			e.Coordinate = lantrace.CoordinateRepeated
		} else if item.complete != nil {
			e.Candidate = lantrace.CandidateCompleteness
		}
		if item.complete != nil {
			e.Cert = lantrace.CertPresent
		} else if item.certificateDrop != "" {
			e.Cert, e.CertDrop = lantrace.CertDropped, item.certificateDrop
		}
		if item.search != "" {
			e.Search = item.search
		}
	}
	if d.horizon == 0 {
		e.Proof = lantrace.ProofAbsent
	}
	return v3CacheTraceResult(e, result)
}

func v3CacheTraceResult(e lantrace.Event, result v3CacheResult) lantrace.Event {
	e.CacheResult, e.MissReason = lantrace.CacheMiss, ""
	if result == v3CacheHit {
		e.CacheResult = lantrace.CachePositive
	} else {
		e.MissReason = lantrace.MissReason(v3CacheResultNames[result])
	}
	if result == v3CacheHorizon && e.Proof != lantrace.ProofAbsent {
		e.Proof = lantrace.ProofExpired
	}
	return e
}

// Final means physically exposed, not merely accepted by the write-boundary
// check. The ordinary-read retry does not emit a second candidate or rescue.
func (c *v3CachedReply) traceFinal(trace v3RequestTrace, exposed bool) {
	e := c.trace
	e.Phase = lantrace.PhaseFinal
	e.Exposure = lantrace.ExposureAccepted
	if !exposed {
		reason := c.finalReason
		if reason == v3CacheHit {
			reason = v3CacheTerminal
		}
		e = v3CacheTraceResult(e, reason)
		e.Exposure = lantrace.ExposureOrdinaryRead
	}
	trace.emit(e)
}
