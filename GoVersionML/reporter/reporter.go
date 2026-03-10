package reporter

import (
	"fmt"
	"io"
	"sort"
	"time"

	"goversion/models"
)

// PrintSummary handles the presentation logic: formatting, sorting, and writing
// the ML results to the provided output stream.
func PrintSummary(out io.Writer, results []models.MLResult, totalRecords int64, duration time.Duration) {
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

	fmt.Fprintf(out, "\n[Top Benign Background Noise (For Contrast)]\n")
	benignPrinted := 0
	for _, res := range results {
		if !res.IsBotnet && benignPrinted < 5 {
			fmt.Fprintf(out, "[BENIGN TRAFFIC ] IP: %-15s | ML Probability: %6.2f%%\n", res.IP, res.Probability)
			benignPrinted++
		}
	}

	fmt.Fprintf(out, "\nDone. Processed %d records.\n", totalRecords)
	fmt.Fprintf(out, "Identified %d specific Botnet IPs out of %d total communicating IPs.\n", botnetCount, len(results))
	fmt.Fprintf(out, "Execution time: %.4f seconds\n", duration.Seconds())
}
