package main

import "log"

// RecordAggregator abstracts aggregation so the detector can be tested with mocks.
type RecordAggregator interface {
	Update(record NetflowRecord)
	UpdatePairState(record NetflowRecord, isSuspiciousPort bool, isSmallPacket bool) *pairState
	ConnectionCount(srcIP string) int
	IPReuseCount(srcIP, dstIP string) int
	UniquePeerCount(srcIP string) int

	PairState(srcIP, dstIP string) *pairState
}

// FeatureScorer abstracts scoring so the detector can be tested with mocks.
type FeatureScorer interface {
	TriggerFeature(ip, feature string)
	Results() []IPScore
	TotalPossibleWeight() float64
}

// Detector orchestrates the detection pipeline: aggregation → rule evaluation → scoring.
// It delegates each responsibility to focused components.
type Detector struct {
	config     *Config
	lookups    *Lookups
	aggregator RecordAggregator
	scorer     FeatureScorer
	rules      []RuleFunc
}

// NewDetector creates a ready-to-use Detector from a Config.
func NewDetector(config *Config) *Detector {
	lookups := NewLookups(config)
	scorer := NewScorer(config)

	log.Printf("Loaded rules: %d suspicious ports, %d known C2 IPs, total weight: %.0f",
		len(lookups.SuspiciousPortSet), len(lookups.KnownC2IPSet),
		scorer.TotalPossibleWeight())

	return &Detector{
		config:     config,
		lookups:    lookups,
		aggregator: NewAggregator(),
		scorer:     scorer,
		rules:      AllRules(),
	}
}

// ProcessRecord processes a single netflow record through the full pipeline:
// 1. Update aggregation state
// 2. Update compound-rule pair state
// 3. Evaluate all rules
func (d *Detector) ProcessRecord(record NetflowRecord) {
	srcIP := record.Src4Addr
	if srcIP == "" {
		return
	}

	// Step 1: Update simple aggregation state
	d.aggregator.Update(record)

	// Step 2: Update compound-rule pair state (needs lookups to set flags)
	if record.Dst4Addr != "" {
		isSuspiciousPort := d.lookups.SuspiciousPortSet[record.DstPort]

		th := &d.config.Thresholds
		isSmallPacket := record.InPackets >= th.MinPacketsForAvg &&
			record.InPackets > 0 &&
			record.InBytes/record.InPackets < th.SmallAvgPacketBytes

		d.aggregator.UpdatePairState(record, isSuspiciousPort, isSmallPacket)
	}

	// Step 3: Evaluate all rules (simple and compound)
	ctx := &RuleContext{
		SrcIP:   srcIP,
		Record:  record,
		Agg:     d.aggregator,
		Config:  d.config,
		Lookups: d.lookups,
	}
	for _, rule := range d.rules {
		if triggered, feature := rule(ctx); triggered {
			d.scorer.TriggerFeature(srcIP, feature)
		}
	}
}

// Results returns scored detection results, sorted by risk factor descending.
func (d *Detector) Results() []IPScore {
	return d.scorer.Results()
}
