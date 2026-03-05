package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"time"
)

func main() {
	// Parse flags
	outputFile := flag.String("o", "", "Write results to a text file (in addition to console)")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [flags] <netflow.json>\n\nFlags:\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	// Load config and create detector
	config, err := LoadConfig("rules.json")
	if err != nil {
		log.Fatalf("Error loading config: %v", err)
	}
	detector := NewDetector(config)

	// Get netflow path from remaining args
	netflowPath := "../test_netflow.json"
	if flag.NArg() > 0 {
		netflowPath = flag.Arg(0)
	}

	// Set up output writers (console + optional file)
	var writers []io.Writer
	writers = append(writers, os.Stdout)

	if *outputFile != "" {
		f, err := os.Create(*outputFile)
		if err != nil {
			log.Fatalf("Error creating output file: %v", err)
		}
		defer f.Close()
		writers = append(writers, f)
	}
	out := io.MultiWriter(writers...)

	fmt.Fprintf(out, "Scanning %s...\n", netflowPath)
	start := time.Now()

	// Open file and use streaming JSON decoder for memory efficiency
	file, err := os.Open(netflowPath)
	if err != nil {
		log.Fatalf("Error opening netflow file: %v", err)
	}
	defer file.Close()

	decoder := json.NewDecoder(file)

	// Expect opening bracket of JSON array
	token, err := decoder.Token()
	if err != nil {
		log.Fatalf("Error reading JSON: %v", err)
	}
	if delim, ok := token.(json.Delim); !ok || delim != '[' {
		log.Fatalf("Expected JSON array, got %v", token)
	}

	var totalRecords int64

	// Stream through records one by one (no full array in memory)
	for decoder.More() {
		var record NetflowRecord
		if err := decoder.Decode(&record); err != nil {
			log.Printf("Error decoding record: %v", err)
			continue
		}
		totalRecords++
		detector.ProcessRecord(record)
	}

	// Compute and display results
	results := detector.Results()

	fmt.Fprintln(out)
	for _, score := range results {
		reasons := make([]string, 0, len(score.TriggeredReasons))
		for r := range score.TriggeredReasons {
			reasons = append(reasons, r)
		}
		fmt.Fprintf(out, "Suspicious IP: %s - Reasons: %s - Risk Factor: %.2f%%\n",
			score.IP, strings.Join(reasons, ", "), score.RiskFactor)
	}

	elapsed := time.Since(start)
	fmt.Fprintf(out, "\nDone. Processed %d records (%d suspicious IPs)\n",
		totalRecords, len(results))
	fmt.Fprintf(out, "Execution time: %.4f seconds\n", elapsed.Seconds())

	if *outputFile != "" {
		fmt.Printf("Results written to: %s\n", *outputFile)
	}
}
