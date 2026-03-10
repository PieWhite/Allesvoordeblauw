package scanner

import (
	"encoding/json"
	"fmt"
	"io"
	"log"

	"goversion/models"
)

func StreamNetflow(stream io.Reader, processFn func(record models.NetflowRecord)) error {
	decoder := json.NewDecoder(stream)

	// Expect opening bracket of the JSON array
	token, err := decoder.Token()
	if err != nil {
		return fmt.Errorf("error reading JSON: %w", err)
	}
	if token != json.Delim('[') {
		return fmt.Errorf("expected JSON array opening bracket, got %v", token)
	}

	for decoder.More() {
		var record models.NetflowRecord
		if err := decoder.Decode(&record); err != nil {
			log.Printf("Error decoding record, skipping: %v", err)
			continue
		}
		processFn(record)
	}

	return nil
}
