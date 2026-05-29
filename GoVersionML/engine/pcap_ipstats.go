package engine

import (
	"math"
	"sort"
	"strings"

	"goversion/models"
)

// PcapIPStats accumulates packet-level characteristics for a specific IP and window
type PcapIPStats struct {
	IP          string
	Window      int64
	PacketCount int
	TotalLength float64
	MinLength   float64
	MaxLength   float64
	Lengths     []float64
	Timestamps  []float64

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

func NewPcapIPStats(ip string, window int64) *PcapIPStats {
	return &PcapIPStats{
		IP:          ip,
		Window:      window,
		MinLength:   math.MaxFloat64,
		MaxLength:   -math.MaxFloat64,
		Lengths:     make([]float64, 0, 100),
		Timestamps:  make([]float64, 0, 100),
	}
}

// Update adds a single packet record's metrics to the IP's stats
func (s *PcapIPStats) Update(record models.PcapRecord, isOutbound bool) {
	s.PacketCount++
	length := float64(record.Length)
	s.TotalLength += length
	s.Lengths = append(s.Lengths, length)
	s.Timestamps = append(s.Timestamps, record.Timestamp)

	if length < s.MinLength {
		s.MinLength = length
	}
	if length > s.MaxLength {
		s.MaxLength = length
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

// ToPcapMLVector computes the final 39 statistical and protocol features of the CICIoT2023 schema
func (s *PcapIPStats) ToPcapMLVector() []float64 {
	fc := float64(s.PacketCount)
	if fc == 0 {
		return make([]float64, 39)
	}

	// A. Header Length and TTL defaults
	// Header Length: Mean transport layer header size (TCP=20, UDP=8, ICMP=8)
	headerSum := float64(s.TCPCount)*20.0 + float64(s.UDPCount+s.ICMPCount)*8.0
	avgHeaderLen := headerSum / fc
	avgTTL := 64.0 // fallback: Mirai/Linux standard default TTL
	if s.PacketCount > 0 {
		avgTTL = float64(s.TTLSum) / fc
	}

	// B. Transmission Rate
	var rate float64
	var iatMean float64
	var iat []float64

	if len(s.Timestamps) > 1 {
		sort.Float64s(s.Timestamps)
		duration := s.Timestamps[len(s.Timestamps)-1] - s.Timestamps[0]
		if duration > 0 {
			rate = fc / duration
		}

		iat = make([]float64, len(s.Timestamps)-1)
		var iatSum float64
		for i := 1; i < len(s.Timestamps); i++ {
			diff := s.Timestamps[i] - s.Timestamps[i-1]
			if diff < 0 {
				diff = 0
			}
			iat[i-1] = diff
			iatSum += diff
		}
		iatMean = iatSum / float64(len(iat))
	}

	// C. Packet Length Statistics
	var lengthSum float64
	for _, l := range s.Lengths {
		lengthSum += l
	}
	avgLength := lengthSum / fc

	var lengthVar float64
	var lengthStd float64
	if len(s.Lengths) > 1 {
		var sumSq float64
		for _, l := range s.Lengths {
			sumSq += (l - avgLength) * (l - avgLength)
		}
		lengthVar = sumSq / float64(len(s.Lengths)-1) // ddof=1 sample variance
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

	// Build and return the vector — order matches CICIoT2023 extracted features
	return []float64{
		avgHeaderLen,                       // 1:  Header Length
		avgTTL,                             // 2:  Time-To-Live
		rate,                               // 3:  Rate
		float64(s.FinCount) / fc,           // 4:  fin flag number
		float64(s.SynCount) / fc,           // 5:  syn flag number
		float64(s.RstCount) / fc,           // 6:  rst flag number
		float64(s.PshCount) / fc,           // 7:  psh flag number
		float64(s.AckCount) / fc,           // 8:  ack flag number
		float64(s.EceCount) / fc,           // 9:  ece flag number
		float64(s.CwrCount) / fc,           // 10: cwr flag number
		float64(s.SynCount),                // 11: syn count
		float64(s.AckCount),                // 12: ack count
		float64(s.FinCount),                // 13: fin count
		float64(s.RstCount),                // 14: rst count
		float64(s.IGMPCount) / fc,          // 15: IGMP
		float64(s.HTTPSCount) / fc,         // 16: HTTPS
		float64(s.HTTPCount) / fc,          // 17: HTTP
		float64(s.TelnetCount) / fc,        // 18: Telnet
		float64(s.DNSCount) / fc,           // 19: DNS
		float64(s.SMTPCount) / fc,          // 20: SMTP
		float64(s.SSHCount) / fc,           // 21: SSH
		float64(s.IRCCount) / fc,           // 22: IRC
		float64(s.TCPCount) / fc,           // 23: TCP
		float64(s.UDPCount) / fc,           // 24: UDP
		float64(s.DHCPCount) / fc,          // 25: DHCP
		float64(s.ARPCount) / fc,           // 26: ARP
		float64(s.ICMPCount) / fc,          // 27: ICMP
		float64(s.IPvCount) / fc,           // 28: IPv
		float64(s.LLCCount) / fc,           // 29: LLC
		s.TotalLength,                      // 30: Tot Sum
		minL,                               // 31: Min
		maxL,                               // 32: Max
		avgLength,                          // 33: AVG
		lengthStd,                          // 34: Std
		avgLength,                          // 35: Tot Size (Average packet length)
		iatMean,                            // 36: IAT
		fc,                                 // 37: Number
		lengthVar,                          // 38: Variance
		modeProto,                          // 39: Protocol Type
	}
}
