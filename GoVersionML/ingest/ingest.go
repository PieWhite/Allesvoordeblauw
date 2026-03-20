package ingest

import (
	"bufio"
	"encoding/csv"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"goversion/models"
	"goversion/scanner" // Import your actual scanner package here
)

// InputFormat is the canonical input type understood by ingestion.
//
// Contract (step 1):
//   - Existing .json ingestion remains supported and unchanged.
//   - .netflow is accepted as a first-class input format at selection level.
//   - Selection is extension-based and case-insensitive.
//   - Unsupported extensions return explicit errors.
//
// NOTE: Netflow text parsing is intentionally not implemented in this step.
// This file establishes stable routing/abstraction seams for step 3+.
type InputFormat string

const (
	InputFormatJSON    InputFormat = "json"
	InputFormatNetflow InputFormat = "netflow"
)

// DetectInputFormatByPath resolves the ingestion format from a file path.
func DetectInputFormatByPath(path string) (InputFormat, error) {
	extension := strings.ToLower(filepath.Ext(path))
	switch extension {
	case ".json":
		return InputFormatJSON, nil
	case ".netflow", ".binetflow":
		return InputFormatNetflow, nil
	default:
		return "", fmt.Errorf("unsupported file extension: %s", extension)
	}
}

// NetflowScanner defines the interface for streaming records.
// This allows us to swap the real scanner for a mock during testing.
type Scanner interface {
	StreamNetflow(r io.Reader, fn func(models.NetflowRecord)) error
}

// Parser defines a format-specific parser that reads records from a stream.
//
// Step 3 contract:
//   - Parse returns canonical records consumed by the existing detection pipeline.
//   - Callers keep ownership of downstream processing (e.g. detector.ProcessRecord).
//   - Format selection happens outside parser implementations (factory).
type Parser interface {
	Parse(r io.Reader) ([]models.NetflowRecord, error)
}

// RealScanner is the production implementation.
// It acts as an adapter that calls the package-level scanner.StreamNetflow.
type JSONScanner struct{}

func (rs *JSONScanner) StreamNetflow(r io.Reader, fn func(models.NetflowRecord)) error {
	return scanner.StreamNetflow(r, fn)
}

// JSONParser adapts the existing streaming scanner into the new Parser interface.
type JSONParser struct {
	Scanner Scanner
}

func (p *JSONParser) Parse(r io.Reader) ([]models.NetflowRecord, error) {
	if p == nil || p.Scanner == nil {
		return nil, fmt.Errorf("scanner not initialized")
	}

	records := make([]models.NetflowRecord, 0)
	err := p.Scanner.StreamNetflow(r, func(record models.NetflowRecord) {
		records = append(records, record)
	})
	if err != nil {
		return nil, err
	}

	return records, nil
}

type NetflowParser struct{}

func (p *NetflowParser) Parse(r io.Reader) ([]models.NetflowRecord, error) {
	scanner := bufio.NewScanner(r)
	records := make([]models.NetflowRecord, 0)
	block := make(map[string]string)
	inBlock := false

	flushBlock := func() {
		if len(block) == 0 {
			return
		}
		if rec, ok := parseRawBlockRecord(block); ok {
			records = append(records, rec)
		}
		block = make(map[string]string)
		inBlock = false
	}

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if strings.HasPrefix(line, "Flow Record") {
			flushBlock()
			inBlock = true
			continue
		}

		if inBlock {
			if line == "" {
				flushBlock()
				continue
			}
			if k, v, ok := parseKVLine(line); ok {
				block[k] = v
			}
			continue
		}

		if shouldSkipNetflowLine(line) {
			continue
		}

		record, ok := parseNetflowLine(line)
		if !ok {
			continue
		}

		records = append(records, record)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read netflow input: %w", err)
	}

	flushBlock()

	return records, nil
}

func parseKVLine(line string) (string, string, bool) {
	idx := strings.Index(line, "=")
	if idx == -1 {
		return "", "", false
	}
	key := strings.ToLower(strings.TrimSpace(line[:idx]))
	value := strings.TrimSpace(line[idx+1:])
	if key == "" {
		return "", "", false
	}
	return key, value, true
}

func parseRawBlockRecord(fields map[string]string) (models.NetflowRecord, bool) {
	proto := parseLeadingInt(fields["proto"])
	srcPort := parseLeadingInt(fields["src port"])
	dstPort := parseLeadingInt(fields["dst port"])
	inPackets := int64(parseLeadingInt(fields["in packets"]))
	inBytes := int64(parseLeadingInt(fields["in bytes"]))

	srcIP := firstToken(fields["src addr"])
	dstIP := firstToken(fields["dst addr"])
	if net.ParseIP(srcIP) == nil || net.ParseIP(dstIP) == nil {
		return models.NetflowRecord{}, false
	}

	first := extractBracketTimestamp(fields["first"])
	last := extractBracketTimestamp(fields["last"])
	received := extractBracketTimestamp(fields["received at"])

	tcpFlags := ""
	if v := fields["tcp flags"]; v != "" {
		parts := strings.Fields(v)
		if len(parts) > 1 {
			tcpFlags = parts[len(parts)-1]
		} else {
			tcpFlags = v
		}
	}

	return models.NetflowRecord{
		Type:      "FLOW",
		Proto:     proto,
		TCPFlags:  strings.TrimSpace(tcpFlags),
		SrcPort:   srcPort,
		DstPort:   dstPort,
		InPackets: inPackets,
		InBytes:   inBytes,
		Src4Addr:  srcIP,
		Dst4Addr:  dstIP,
		First:     normalizeTimeString(first),
		Last:      normalizeTimeString(last),
		Received:  normalizeTimeString(received),
	}, true
}

func parseLeadingInt(v string) int {
	tokens := strings.Fields(strings.TrimSpace(v))
	if len(tokens) == 0 {
		return 0
	}
	n, _ := strconv.Atoi(tokens[0])
	return n
}

func firstToken(v string) string {
	tokens := strings.Fields(strings.TrimSpace(v))
	if len(tokens) == 0 {
		return ""
	}
	return tokens[0]
}

func extractBracketTimestamp(v string) string {
	start := strings.Index(v, "[")
	end := strings.LastIndex(v, "]")
	if start >= 0 && end > start {
		return strings.TrimSpace(v[start+1 : end])
	}
	return strings.TrimSpace(v)
}

func shouldSkipNetflowLine(line string) bool {
	if line == "" {
		return true
	}

	lower := strings.ToLower(line)
	if strings.HasPrefix(line, "#") ||
		strings.Contains(lower, "date first seen") ||
		strings.HasPrefix(lower, "ts,te,") {
		return true
	}

	return false
}

func parseNetflowLine(line string) (models.NetflowRecord, bool) {
	if strings.Contains(line, "|") {
		return parsePipeNetflowLine(line)
	}

	if strings.Contains(line, ",") {
		return parseCSVNetflowLine(line)
	}

	return parseTextNetflowLine(line)
}

func parsePipeNetflowLine(line string) (models.NetflowRecord, bool) {
	parts := strings.Split(line, "|")
	if len(parts) < 22 {
		return models.NetflowRecord{}, false
	}

	srcIP, ok := parseUint32IP(parts[7])
	if !ok {
		return models.NetflowRecord{}, false
	}
	dstIP, ok := parseUint32IP(parts[12])
	if !ok {
		return models.NetflowRecord{}, false
	}

	protoNum, _ := strconv.Atoi(strings.TrimSpace(parts[3]))
	srcPort := parseIntDefault(parts[8], 0)
	dstPort := parseIntDefault(parts[13], 0)
	packets := parseInt64Default(parts[20], 0)
	bytes := parseInt64Default(parts[21], 0)
	flagsVal := parseIntDefault(parts[18], 0)
	firstMillis := parseInt64Default(parts[1], 0)
	lastMillis := parseInt64Default(parts[2], firstMillis)

	return models.NetflowRecord{
		Type:      "FLOW",
		Proto:     protoNum,
		TCPFlags:  strconv.Itoa(flagsVal),
		SrcPort:   srcPort,
		DstPort:   dstPort,
		InPackets: packets,
		InBytes:   bytes,
		Src4Addr:  srcIP,
		Dst4Addr:  dstIP,
		First:     millisToRFC3339(firstMillis),
		Last:      millisToRFC3339(lastMillis),
		Received:  millisToRFC3339(lastMillis),
	}, true
}

func parseCSVNetflowLine(line string) (models.NetflowRecord, bool) {
	r := csv.NewReader(strings.NewReader(line))
	r.FieldsPerRecord = -1
	parts, err := r.Read()
	if err != nil || len(parts) < 13 {
		return models.NetflowRecord{}, false
	}

	proto := strings.ToUpper(strings.TrimSpace(parts[7]))
	protoNum := protoToNumber(proto)
	if protoNum == 0 && proto != "ICMP" {
		return models.NetflowRecord{}, false
	}

	srcIP := strings.TrimSpace(parts[3])
	dstIP := strings.TrimSpace(parts[4])
	if net.ParseIP(srcIP) == nil || net.ParseIP(dstIP) == nil {
		return models.NetflowRecord{}, false
	}

	return models.NetflowRecord{
		Type:      "FLOW",
		Proto:     protoNum,
		TCPFlags:  strings.TrimSpace(parts[8]),
		SrcPort:   parseIntDefault(parts[5], 0),
		DstPort:   parseIntDefault(parts[6], 0),
		InPackets: parseInt64Default(parts[11], 0),
		InBytes:   parseInt64Default(parts[12], 0),
		Src4Addr:  srcIP,
		Dst4Addr:  dstIP,
		First:     normalizeTimeString(parts[0]),
		Last:      normalizeTimeString(parts[1]),
		Received:  normalizeTimeString(lastOr(parts[1], parts[0])),
	}, true
}

func parseTextNetflowLine(line string) (models.NetflowRecord, bool) {
	if !strings.Contains(line, "->") {
		return models.NetflowRecord{}, false
	}

	tokens := strings.Fields(line)
	if len(tokens) < 9 {
		return models.NetflowRecord{}, false
	}

	protoIdx := -1
	for i, tok := range tokens {
		u := strings.ToUpper(tok)
		if u == "TCP" || u == "UDP" || u == "ICMP" {
			protoIdx = i
			break
		}
	}
	if protoIdx == -1 || protoIdx+3 >= len(tokens) {
		return models.NetflowRecord{}, false
	}

	dateTime := strings.TrimSpace(tokens[0] + " " + tokens[1])
	proto := strings.ToUpper(tokens[protoIdx])
	src := tokens[protoIdx+1]
	arrow := tokens[protoIdx+2]
	dst := tokens[protoIdx+3]
	if arrow != "->" {
		return models.NetflowRecord{}, false
	}

	srcIP, srcPort, ok := splitIPPort(src)
	if !ok {
		return models.NetflowRecord{}, false
	}
	dstIP, dstPort, ok := splitIPPort(dst)
	if !ok {
		return models.NetflowRecord{}, false
	}

	packets, bytes := extractPacketsAndBytes(tokens, protoIdx+4)

	return models.NetflowRecord{
		Type:      "FLOW",
		Proto:     protoToNumber(proto),
		TCPFlags:  extractLikelyFlags(tokens, protoIdx+4),
		SrcPort:   srcPort,
		DstPort:   dstPort,
		InPackets: packets,
		InBytes:   bytes,
		Src4Addr:  srcIP,
		Dst4Addr:  dstIP,
		First:     normalizeTimeString(dateTime),
		Last:      normalizeTimeString(dateTime),
		Received:  normalizeTimeString(dateTime),
	}, true
}

func parseUint32IP(v string) (string, bool) {
	n, err := strconv.ParseUint(strings.TrimSpace(v), 10, 32)
	if err != nil {
		return "", false
	}
	b := []byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
	ip := net.IPv4(b[0], b[1], b[2], b[3]).String()
	if net.ParseIP(ip) == nil {
		return "", false
	}
	return ip, true
}

func parseIntDefault(v string, def int) int {
	i, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil {
		return def
	}
	return i
}

func parseInt64Default(v string, def int64) int64 {
	i, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
	if err != nil {
		return def
	}
	return i
}

func millisToRFC3339(ms int64) string {
	if ms <= 0 {
		return ""
	}
	return time.Unix(0, ms*int64(time.Millisecond)).UTC().Format(time.RFC3339Nano)
}

func protoToNumber(proto string) int {
	switch strings.ToUpper(strings.TrimSpace(proto)) {
	case "ICMP":
		return 1
	case "TCP":
		return 6
	case "UDP":
		return 17
	default:
		return 0
	}
}

func normalizeTimeString(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	layouts := []string{
		"2006-01-02 15:04:05.999",
		"2006-01-02 15:04:05",
		time.RFC3339,
		time.RFC3339Nano,
	}
	for _, layout := range layouts {
		if t, err := time.Parse(layout, v); err == nil {
			return t.UTC().Format(time.RFC3339Nano)
		}
	}
	return v
}

func lastOr(v string, fallback string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return fallback
	}
	return v
}

func splitIPPort(v string) (string, int, bool) {
	v = strings.TrimSpace(v)
	idx := strings.LastIndex(v, ":")
	if idx <= 0 || idx >= len(v)-1 {
		return "", 0, false
	}
	ip := strings.TrimSpace(v[:idx])
	portRaw := strings.TrimSpace(v[idx+1:])
	if net.ParseIP(ip) == nil {
		return "", 0, false
	}
	if strings.Contains(portRaw, ".") {
		portRaw = strings.SplitN(portRaw, ".", 2)[0]
	}
	port := parseIntDefault(portRaw, 0)
	if port < 0 {
		port = 0
	}
	return ip, port, true
}

func extractPacketsAndBytes(tokens []string, start int) (int64, int64) {
	packets := int64(0)
	bytes := int64(0)

	for i := start; i < len(tokens); i++ {
		tok := strings.TrimSpace(tokens[i])
		if tok == "" {
			continue
		}

		if packets == 0 {
			if v, ok := parseMaybeScaledInt(tok, ""); ok {
				packets = v
				continue
			}
		}

		if bytes == 0 {
			suffix := ""
			if i+1 < len(tokens) {
				next := strings.TrimSpace(tokens[i+1])
				if next == "K" || next == "M" || next == "G" {
					suffix = next
					i++
				}
			}
			if v, ok := parseMaybeScaledInt(tok, suffix); ok {
				bytes = v
			}
		}

		if packets > 0 && bytes > 0 {
			break
		}
	}

	return packets, bytes
}

func parseMaybeScaledInt(token string, suffix string) (int64, bool) {
	token = strings.TrimSpace(token)
	suffix = strings.ToUpper(strings.TrimSpace(suffix))
	if token == "" {
		return 0, false
	}

	multiplier := float64(1)
	if strings.HasSuffix(strings.ToUpper(token), "K") || strings.HasSuffix(strings.ToUpper(token), "M") || strings.HasSuffix(strings.ToUpper(token), "G") {
		suffix = strings.ToUpper(token[len(token)-1:])
		token = token[:len(token)-1]
	}

	switch suffix {
	case "K":
		multiplier = 1_000
	case "M":
		multiplier = 1_000_000
	case "G":
		multiplier = 1_000_000_000
	}

	f, err := strconv.ParseFloat(token, 64)
	if err != nil {
		return 0, false
	}

	return int64(f * multiplier), true
}

func extractLikelyFlags(tokens []string, start int) string {
	for i := start; i < len(tokens); i++ {
		tok := strings.TrimSpace(tokens[i])
		if strings.Contains(tok, ".") || strings.ContainsAny(tok, "SAPFRU") {
			if len(tok) >= 6 && len(tok) <= 12 {
				return tok
			}
		}
	}
	return ""
}

// NewParserByPath auto-selects a parser based on file extension.
func NewParserByPath(path string, scanner Scanner) (Parser, error) {
	return NewParserByPathWithOverride(path, scanner, "")
}

func NewParserByPathWithOverride(path string, scanner Scanner, explicit InputFormat) (Parser, error) {
	format := explicit
	if format == "" {
		var err error
		format, err = DetectInputFormatByPath(path)
		if err != nil {
			return nil, err
		}
	}

	switch format {
	case InputFormatJSON:
		return &JSONParser{Scanner: scanner}, nil
	case InputFormatNetflow:
		return &NetflowParser{}, nil
	default:
		return nil, fmt.Errorf("unsupported input format: %s", format)
	}
}

// Ingestor manages the input lifecycle and dependency injection.
type Ingestor struct {
	NetflowScanner Scanner
	ParserFactory  func(path string, scanner Scanner) (Parser, error)
	InputFormat    InputFormat
}

// ProcessInput detects the file type, opens it, and delegates to the scanner.
func (i *Ingestor) ProcessInput(path string, processFn func(record models.NetflowRecord)) error {
	// 1. Open the resource securely
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("failed to open input file: %w", err)
	}
	defer file.Close()

	factory := i.ParserFactory
	if factory == nil {
		factory = NewParserByPath
	}

	// 2. Resolve parser based on input format/path.
	var parser Parser
	if i.InputFormat != "" {
		parser, err = NewParserByPathWithOverride(path, i.NetflowScanner, i.InputFormat)
	} else {
		parser, err = factory(path, i.NetflowScanner)
	}
	if err != nil {
		return err
	}

	// 3. Parse and pass canonical records through existing pipeline callback.
	records, err := parser.Parse(file)
	if err != nil {
		return err
	}

	for _, record := range records {
		processFn(NormalizeNetflowRecord(record))
	}

	return nil
}

// NormalizeNetflowRecord converts parser output into a canonical record shape
// expected by downstream detection and aggregation.
func NormalizeNetflowRecord(record models.NetflowRecord) models.NetflowRecord {
	n := record

	if n.Type == "" {
		n.Type = "FLOW"
	}

	n.Proto = normalizeProto(n.Proto, n.TCPFlags)
	n.Src4Addr = normalizeIP(n.Src4Addr)
	n.Dst4Addr = normalizeIP(n.Dst4Addr)
	n.SrcPort = clampPort(n.SrcPort)
	n.DstPort = clampPort(n.DstPort)
	n.InPackets = clampInt64Min(n.InPackets, 0)
	n.InBytes = clampInt64Min(n.InBytes, 0)

	n.First = normalizeTimestampForAggregator(n.First)
	n.Last = normalizeTimestampForAggregator(lastOr(n.Last, n.First))
	n.Received = normalizeTimestampForAggregator(lastOr(n.Received, n.Last))

	if n.Last == "" {
		n.Last = n.First
	}
	if n.Received == "" {
		n.Received = n.Last
	}

	return n
}

func normalizeProto(proto int, flags string) int {
	switch proto {
	case 1, 6, 17:
		return proto
	}

	f := strings.ToUpper(flags)
	if strings.ContainsAny(f, "SAPFRU") {
		return 6
	}

	return proto
}

func normalizeIP(v string) string {
	v = strings.TrimSpace(v)
	ip := net.ParseIP(v)
	if ip == nil {
		return ""
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.String()
}

func clampPort(v int) int {
	if v < 0 {
		return 0
	}
	if v > 65535 {
		return 65535
	}
	return v
}

func clampInt64Min(v int64, min int64) int64 {
	if v < min {
		return min
	}
	return v
}

func normalizeTimestampForAggregator(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}

	layouts := []string{
		"2006-01-02T15:04:05.000",
		"2006-01-02T15:04:05",
		"2006-01-02 15:04:05.999",
		"2006-01-02 15:04:05",
		time.RFC3339,
		time.RFC3339Nano,
	}

	for _, layout := range layouts {
		if t, err := time.Parse(layout, v); err == nil {
			return t.UTC().Format("2006-01-02T15:04:05.000")
		}
	}

	return ""
}
