package engine

import (
	"os"
	"path/filepath"
	"testing"

	"goversion/models"
)

func findTestPcapModel() string {
	// Look for the copied placeholder pcap model
	p := filepath.Join("..", "Xgboost", "pcap_xgboost.json")
	if _, err := os.Stat(p); err == nil {
		return p
	}
	return filepath.Join("Xgboost", "pcap_xgboost.json")
}

func TestNewPcapDetector(t *testing.T) {
	// Test loading with invalid path
	_, err := NewPcapDetector("invalid-path-to-json.json")
	if err == nil {
		t.Fatal("Expected error when loading from invalid model path, got nil")
	}

	// Test loading with valid path
	modelPath := findTestPcapModel()
	detector, err := NewPcapDetector(modelPath)
	if err != nil {
		t.Fatalf("Failed to initialize PcapDetector with valid model: %v", err)
	}

	if detector == nil {
		t.Fatal("Expected non-nil PcapDetector")
	}
}

func TestPcapDetector_ProcessAndFlush(t *testing.T) {
	modelPath := findTestPcapModel()
	detector, err := NewPcapDetector(modelPath)
	if err != nil {
		t.Fatalf("Failed to initialize PcapDetector: %v", err)
	}

	// Send a packet in window 1680000000 (timestamp 1680000000)
	detector.ProcessPcapRecords([]models.PcapRecord{
		{
			Timestamp: 1680000000,
			Length:    100,
			Proto:     6,
			SrcIP:     "192.168.1.1",
			DstIP:     "192.168.1.2",
			TCPFlags:  "S",
		},
	})

	if count := detector.TotalCount(); count != 1 {
		t.Errorf("Expected total count 1, got %d", count)
	}

	// Send another packet that advances the window past the 5-minute threshold (1680000000 + 350)
	detector.ProcessPcapRecords([]models.PcapRecord{
		{
			Timestamp: 1680000350,
			Length:    200,
			Proto:     6,
			SrcIP:     "192.168.1.1",
			DstIP:     "192.168.1.2",
			TCPFlags:  "A",
		},
	})

	// Calling CalculateResults should trigger Flush and evaluate all batches
	results := detector.CalculateResults()

	// Verify we got results back
	if len(results) == 0 {
		t.Errorf("Expected classification results, got empty list")
	}

	// The processed records should correspond to the flushed IP
	foundIP := false
	for _, res := range results {
		if res.IP == "192.168.1.1" {
			foundIP = true
			break
		}
	}
	if !foundIP {
		t.Errorf("Expected result for IP 192.168.1.1, not found in results: %+v", results)
	}
}
