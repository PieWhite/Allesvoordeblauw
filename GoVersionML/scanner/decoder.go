package scanner

import (
	"bytes"

	"github.com/goccy/go-json"

	"goversion/models"
)

func wrapChunk(chunk []byte) []byte {
	cleanChunk := bytes.Trim(bytes.TrimSpace(chunk), "[], \n\r\t")
	if len(cleanChunk) == 0 {
		return nil
	}

	wrapped := make([]byte, 0, len(cleanChunk)+2)
	wrapped = append(wrapped, '[')
	wrapped = append(wrapped, cleanChunk...)
	wrapped = append(wrapped, ']')

	return wrapped
}

func decodeChunk(chunk []byte) ([]models.NetflowRecord, []byte, error) {
	wrapped := wrapChunk(chunk)
	if wrapped == nil {
		return nil, nil, nil
	}

	var records []models.NetflowRecord

	if err := json.Unmarshal(wrapped, &records); err != nil {
		return nil, wrapped, err
	}

	return records, nil, nil
}
