package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"time"
)

func main() {
	// Load config and create detector
	config, err := LoadConfig("rules.json")
	if err != nil {
		log.Fatalf("Error loading config: %v", err)
	}
	detector := NewDetector(config)

	// Default to the sample netflow file, or accept a path as argument
	netflowPath := "../test_netflow.json"
	if len(os.Args) > 1 {
		netflowPath = os.Args[1]
	}

	fmt.Printf("Scanning %s...\n", netflowPath)
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

	fmt.Println()
	for _, score := range results {
		reasons := make([]string, 0, len(score.TriggeredReasons))
		for r := range score.TriggeredReasons {
			reasons = append(reasons, r)
		}
		fmt.Printf("Suspicious IP: %s - Reasons: %s - Risk Factor: %.2f%%\n",
			score.IP, strings.Join(reasons, ", "), score.RiskFactor)
	}

	elapsed := time.Since(start)
	fmt.Printf("\nDone. Processed %d records (%d suspicious IPs)\n",
		totalRecords, len(results))
	fmt.Printf("Execution time: %.4f seconds\n", elapsed.Seconds())
}
