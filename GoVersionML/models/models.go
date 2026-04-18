package models

// MLResult holds the final model prediction for a single IP.

type MLResult struct {
	IP          string
	Probability float64
	IsBotnet    bool
}
