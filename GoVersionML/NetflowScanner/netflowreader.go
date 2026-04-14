package netflowscanner

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"goversion/models"
)

const netflowBatchSize = 4096

// StreamNetflowText parses nfdump text output (.netflow files) directly into
// NetflowRecord batches, completely bypassing JSON parsing overhead.
//
// The format is the structured text output from nfdump (e.g. nfdump -r file -o long),
// with "Flow Record:" delimiters and key=value fields on indented lines.
func StreamNetflowText(stream io.Reader, processFn func([]models.NetflowRecord)) error {
	scanner := bufio.NewScanner(stream)
	scanner.Buffer(make([]byte, 256*1024), 256*1024)

	batch := make([]models.NetflowRecord, 0, netflowBatchSize)
	var current models.NetflowRecord
	inRecord := false

	for scanner.Scan() {
		line := scanner.Text()

		// Detect record boundary
		if strings.HasPrefix(line, "Flow Record:") {
			// Flush previous record
			if inRecord && current.Src4Addr != "" {
				batch = append(batch, current)
				if len(batch) >= netflowBatchSize {
					processFn(batch)
					batch = make([]models.NetflowRecord, 0, netflowBatchSize)
				}
			}
			current = models.NetflowRecord{}
			inRecord = true
			continue
		}

		// Skip non-record lines (summary, empty lines, etc.)
		if !inRecord || len(line) < 4 || line[0] != ' ' {
			continue
		}

		// Parse the key = value pairs. Lines look like:
		//   "  first        =     1739429195920 [2025-02-13 07:46:35.920]"
		//   "  proto        =                 6 TCP"
		//   "  src addr     =    194.180.49.205"
		eqIdx := strings.IndexByte(line, '=')
		if eqIdx == -1 {
			continue
		}

		key := strings.TrimSpace(line[:eqIdx])
		rawValue := strings.TrimSpace(line[eqIdx+1:])

		switch key {
		case "first":
			if ms, ok := parseUnixMs(rawValue); ok {
				current.First = formatTimestamp(ms)
			}
		case "last":
			if ms, ok := parseUnixMs(rawValue); ok {
				current.Last = formatTimestamp(ms)
			}
		case "received at":
			if ms, ok := parseUnixMs(rawValue); ok {
				current.Received = formatTimestamp(ms)
			}
		case "proto":
			current.Proto = parseFirstInt(rawValue)
		case "tcp flags":
			current.TCPFlags = parseTCPFlagsVisual(rawValue)
		case "src port":
			current.SrcPort = parseFirstInt(rawValue)
		case "dst port":
			current.DstPort = parseFirstInt(rawValue)
		case "in packets":
			current.InPackets = parseFirstInt64(rawValue)
		case "in bytes":
			current.InBytes = parseFirstInt64(rawValue)
		case "src addr":
			current.Src4Addr = rawValue
		case "dst addr":
			current.Dst4Addr = rawValue
		case "ip next hop":
			current.IPNextHop = rawValue
		case "in src mac":
			current.InSrcMAC = rawValue
		case "out dst mac":
			current.OutDstMAC = rawValue
		case "export sysid":
			current.ExportSysID = parseFirstInt(rawValue)
		case "ICMP":
			// ICMP records have no src/dst port, just "ICMP = 0.0 type.code"
			current.SrcPort = 0
			current.DstPort = 0
		}
	}

	// Flush last record and remaining batch
	if inRecord && current.Src4Addr != "" {
		batch = append(batch, current)
	}
	if len(batch) > 0 {
		processFn(batch)
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("netflow text scanner error: %w", err)
	}

	return nil
}

// parseUnixMs extracts the Unix milliseconds from a value like "1739429195920 [2025-02-13 07:46:35.920]"
func parseUnixMs(s string) (int64, bool) {
	// The number ends at the first space or bracket
	end := strings.IndexByte(s, ' ')
	if end == -1 {
		end = len(s)
	}
	n, err := strconv.ParseInt(s[:end], 10, 64)
	return n, err == nil
}

// formatTimestamp converts Unix milliseconds to the ISO format the aggregator expects.
func formatTimestamp(ms int64) string {
	t := time.UnixMilli(ms).UTC()
	return t.Format("2006-01-02T15:04:05.000")
}

// parseFirstInt extracts the first integer from a string like "6 TCP" or "443".
func parseFirstInt(s string) int {
	end := 0
	for end < len(s) && (s[end] >= '0' && s[end] <= '9') {
		end++
	}
	if end == 0 {
		return 0
	}
	n, _ := strconv.Atoi(s[:end])
	return n
}

// parseFirstInt64 extracts the first int64 from a string like "1050000".
func parseFirstInt64(s string) int64 {
	end := 0
	for end < len(s) && (s[end] >= '0' && s[end] <= '9') {
		end++
	}
	if end == 0 {
		return 0
	}
	n, _ := strconv.ParseInt(s[:end], 10, 64)
	return n
}

// parseTCPFlagsVisual extracts the visual flags portion from "0x18 ...AP..."
// We need the visual representation because the aggregator checks for individual flag letters.
func parseTCPFlagsVisual(s string) string {
	// Parse the hex value and convert to flag letters for the aggregator
	if !strings.HasPrefix(s, "0x") {
		return "........"
	}

	hexEnd := 2
	for hexEnd < len(s) && s[hexEnd] != ' ' {
		hexEnd++
	}

	val, err := strconv.ParseUint(s[2:hexEnd], 16, 8)
	if err != nil {
		return "........"
	}

	return tcpFlagBitsToString(uint8(val))
}

// tcpFlagBitsToString converts a TCP flags bitmask to the nfdump visual format.
// Bit layout: FIN=0x01, SYN=0x02, RST=0x04, PSH=0x08, ACK=0x10, URG=0x20
func tcpFlagBitsToString(flags uint8) string {
	// nfdump visual format positions: CWR ECN URG ACK PSH RST SYN FIN
	// nfdump outputs: ...AP..F (positions: CWR ECN URG ACK PSH RST SYN FIN)
	// Let's use the exact nfdump visual format the aggregator expects.
	var result [8]byte
	result[0] = flagChar(flags, 0x80, 'C') // CWR
	result[1] = flagChar(flags, 0x40, 'E') // ECN
	result[2] = flagChar(flags, 0x20, 'U') // URG
	result[3] = flagChar(flags, 0x10, 'A') // ACK
	result[4] = flagChar(flags, 0x08, 'P') // PSH
	result[5] = flagChar(flags, 0x04, 'R') // RST
	result[6] = flagChar(flags, 0x02, 'S') // SYN
	result[7] = flagChar(flags, 0x01, 'F') // FIN

	return string(result[:])
}

func flagChar(flags uint8, mask uint8, letter byte) byte {
	if flags&mask != 0 {
		return letter
	}
	return '.'
}


