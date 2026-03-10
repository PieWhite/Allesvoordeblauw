package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"sort"
	"time"
)

func main() {
	// Parse flags
	modelPath := flag.String("m", "botnet_xgboost.json", "Path to the XGBoost JSON dump")
	outputFile := flag.String("o", "", "Write results to a text file (in addition to console)")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [flags] <example_netflow.json>\n\nFlags:\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	// Load the ML detector
	detector := NewDetector(*modelPath)

	// Get netflow path from remaining args
	netflowPath := "../test_netflow.json"
	if flag.NArg() > 0 {
		netflowPath = flag.Arg(0)
	}

	start := time.Now()

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

	fmt.Fprintf(out, "Scanning %s with XGBoost ML Model...\n", netflowPath)

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

	// Stream through records one by one
	for decoder.More() {
		var record NetflowRecord
		if err := decoder.Decode(&record); err != nil {
			log.Printf("Error decoding record: %v", err)
			continue
		}
		totalRecords++
		detector.ProcessRecord(record)
	}

	// Collect ML Results
	fmt.Fprintf(out, "\nAggregated Features. Running XGBoost Inference on %d unique Source IPs...\n", len(detector.aggregator.IPs))

	results := detector.Results()

	// Sort results by Probability descending
	sort.SliceStable(results, func(i, j int) bool {
		return results[i].Probability > results[j].Probability
	})

	fmt.Fprintln(out)

	var botnetCount int
	for _, res := range results {
		if res.IsBotnet {
			botnetCount++
			fmt.Fprintf(out, "[BOTNET DETECTED] IP: %-15s | ML Probability: %6.2f%%\n", res.IP, res.Probability)
		}
	}

	// Print a few benign ones for context
	fmt.Fprintf(out, "\n[Top Benign Background Noise (For Contrast)]\n")
	benignPrinted := 0
	for _, res := range results {
		if !res.IsBotnet && benignPrinted < 5 {
			fmt.Fprintf(out, "[BENIGN TRAFFIC ] IP: %-15s | ML Probability: %6.2f%%\n", res.IP, res.Probability)
			benignPrinted++
		}
	}

	elapsed := time.Since(start)
	fmt.Fprintf(out, "\nDone. Processed %d records.\n", totalRecords)
	fmt.Fprintf(out, "Identified %d specific Botnet IPs out of %d total communicating IPs.\n", botnetCount, len(results))
	fmt.Fprintf(out, "Execution time: %.4f seconds\n", elapsed.Seconds())

	if *outputFile != "" {
		fmt.Printf("Results written to: %s\n", *outputFile)
	}
}
