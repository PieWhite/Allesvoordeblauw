package engine

import (
	"math"
	"strings"

	"goversion/models"
)

// PcapIPStats accumulates packet-level characteristics for a specific IP and window
type PcapIPStats struct {
	IP           uint32
	PacketCount  int
	TotalLength  float64
	MinLength    float64
	MaxLength    float64
	LengthMean   float64
	LengthM2     float64
	MinTimestamp float64
	MaxTimestamp float64

	// TCP Flag Counts
	FinCount int
	SynCount int
	RstCount int
	PshCount int
	AckCount int
	EceCount int
	CwrCount int

	// Protocol and Port Counts
	TCPCount    int
	UDPCount    int
	ICMPCount   int
	IGMPCount   int
	TTLSum      int
	HTTPCount   int
	HTTPSCount  int
	TelnetCount int
	DNSCount    int
	SMTPCount   int
	SSHCount    int
	IRCCount    int
	DHCPCount   int
	ARPCount    int
	IPvCount    int
	LLCCount    int
}

func NewPcapIPStats(ip uint32, window int64) *PcapIPStats {
	return &PcapIPStats{
		IP:           ip,
		MinLength:    math.MaxFloat64,
		MaxLength:    -math.MaxFloat64,
		MinTimestamp: math.MaxFloat64,
		MaxTimestamp: -math.MaxFloat64,
	}
}

// Update adds a single packet record's metrics to the IP's stats
func (s *PcapIPStats) Update(record models.PcapRecord, isOutbound bool) {
	s.PacketCount++
	length := float64(record.Length)
	s.TotalLength += length

	if length < s.MinLength {
		s.MinLength = length
	}
	if length > s.MaxLength {
		s.MaxLength = length
	}

	// Welford's algorithm for online variance
	count := float64(s.PacketCount)
	delta := length - s.LengthMean
	s.LengthMean += delta / count
	delta2 := length - s.LengthMean
	s.LengthM2 += delta * delta2

	if record.Timestamp < s.MinTimestamp {
		s.MinTimestamp = record.Timestamp
	}
	if record.Timestamp > s.MaxTimestamp {
		s.MaxTimestamp = record.Timestamp
	}

	// 1. TCP Flags
	if record.TCPFlags != "" {
		if strings.Contains(record.TCPFlags, "F") {
			s.FinCount++
		}
		if strings.Contains(record.TCPFlags, "S") {
			s.SynCount++
		}
		if strings.Contains(record.TCPFlags, "R") {
			s.RstCount++
		}
		if strings.Contains(record.TCPFlags, "P") {
			s.PshCount++
		}
		if strings.Contains(record.TCPFlags, "A") {
			s.AckCount++
		}
		if strings.Contains(record.TCPFlags, "E") {
			s.EceCount++
		}
		if strings.Contains(record.TCPFlags, "C") {
			s.CwrCount++
		}
	}

	// 2. Protocol Identification
	s.IPvCount++ // All processed packets are IPv4
	s.TTLSum += int(record.TTL)
	switch record.Proto {
	case 1:
		s.ICMPCount++
	case 2:
		s.IGMPCount++
	case 6:
		s.TCPCount++
	case 17:
		s.UDPCount++
	case 2054: // ARP (EtherType 0x0806 used as sentinel)
		s.ARPCount++
	}

	// 3. Port/Protocol Application Layer Identification
	port := record.DstPort
	if isOutbound {
		port = record.DstPort
	} else {
		port = record.SrcPort
	}

	switch port {
	case 80:
		s.HTTPCount++
	case 443:
		s.HTTPSCount++
	case 23:
		s.TelnetCount++
	case 53:
		s.DNSCount++
	case 25:
		s.SMTPCount++
	case 22:
		s.SSHCount++
	case 194, 6667:
		s.IRCCount++
	case 67, 68:
		s.DHCPCount++
	}
}

// FillPcapMLVector populates a preallocated slice (must be length 39) with CICIoT2023 features.
func (s *PcapIPStats) FillPcapMLVector(features []float64) {
	_ = features[38] // Bounds check elimination

	fc := float64(s.PacketCount)
	if fc == 0 {
		for i := 0; i < 39; i++ {
			features[i] = 0
		}
		return
	}

	// A. Header Length and TTL defaults
	headerSum := float64(s.TCPCount)*20.0 + float64(s.UDPCount+s.ICMPCount)*8.0
	avgHeaderLen := headerSum / fc
	avgTTL := 64.0 // fallback: Mirai/Linux standard default TTL
	if s.PacketCount > 0 {
		avgTTL = float64(s.TTLSum) / fc
	}

	// B. Transmission Rate
	var rate float64
	var iatMean float64

	if s.PacketCount > 1 {
		duration := s.MaxTimestamp - s.MinTimestamp
		if duration > 0 {
			rate = fc / duration
		}

		iatSum := s.MaxTimestamp - s.MinTimestamp
		if iatSum < 0 {
			iatSum = 0
		}
		iatMean = iatSum / float64(s.PacketCount-1)
	}

	// C. Packet Length Statistics
	avgLength := s.TotalLength / fc

	var lengthVar float64
	var lengthStd float64
	if s.PacketCount > 1 {
		lengthVar = s.LengthM2 / float64(s.PacketCount-1)
		lengthStd = math.Sqrt(lengthVar)
	}

	// D. Mode Protocol Type
	modeProto := 6.0 // TCP default
	maxCount := s.TCPCount
	if s.UDPCount > maxCount {
		maxCount = s.UDPCount
		modeProto = 17.0
	}
	if s.ICMPCount > maxCount {
		maxCount = s.ICMPCount
		modeProto = 1.0
	}
	if s.IGMPCount > maxCount {
		modeProto = 2.0
	}

	minL := s.MinLength
	if minL == math.MaxFloat64 {
		minL = 0
	}
	maxL := s.MaxLength
	if maxL == -math.MaxFloat64 {
		maxL = 0
	}

	features[0] = avgHeaderLen
	features[1] = avgTTL
	features[2] = rate
	features[3] = float64(s.FinCount) / fc
	features[4] = float64(s.SynCount) / fc
	features[5] = float64(s.RstCount) / fc
	features[6] = float64(s.PshCount) / fc
	features[7] = float64(s.AckCount) / fc
	features[8] = float64(s.EceCount) / fc
	features[9] = float64(s.CwrCount) / fc
	features[10] = float64(s.SynCount)
	features[11] = float64(s.AckCount)
	features[12] = float64(s.FinCount)
	features[13] = float64(s.RstCount)
	features[14] = float64(s.IGMPCount) / fc
	features[15] = float64(s.HTTPSCount) / fc
	features[16] = float64(s.HTTPCount) / fc
	features[17] = float64(s.TelnetCount) / fc
	features[18] = float64(s.DNSCount) / fc
	features[19] = float64(s.SMTPCount) / fc
	features[20] = float64(s.SSHCount) / fc
	features[21] = float64(s.IRCCount) / fc
	features[22] = float64(s.TCPCount) / fc
	features[23] = float64(s.UDPCount) / fc
	features[24] = float64(s.DHCPCount) / fc
	features[25] = float64(s.ARPCount) / fc
	features[26] = float64(s.ICMPCount) / fc
	features[27] = float64(s.IPvCount) / fc
	features[28] = float64(s.LLCCount) / fc
	features[29] = s.TotalLength
	features[30] = minL
	features[31] = maxL
	features[32] = avgLength
	features[33] = lengthStd
	features[34] = avgLength
	features[35] = iatMean
	features[36] = fc
	features[37] = lengthVar
	features[38] = modeProto
}

// ToPcapMLVector computes the final 39 statistical and protocol features of the CICIoT2023 schema
func (s *PcapIPStats) ToPcapMLVector() []float64 {
	vec := make([]float64, 39)
	s.FillPcapMLVector(vec)
	return vec
}
