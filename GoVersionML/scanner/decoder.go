package scanner

import (
	"bytes"
	"sync"

	"github.com/goccy/go-json"

	"goversion/models"
)

var wrapPool = sync.Pool{
	New: func() interface{} {
		return new(bytes.Buffer)
	},
}

func decodeChunkArray(chunk []byte) ([]models.NDJsonRecord, *bytes.Buffer, error) {
	cleanChunk := bytes.Trim(bytes.TrimSpace(chunk), "[], \n\r\t")
	if len(cleanChunk) == 0 {
		return nil, nil, nil
	}

	buf := wrapPool.Get().(*bytes.Buffer)
	buf.Reset()
	buf.Grow(len(cleanChunk) + 2)
	buf.WriteByte('[')
	buf.Write(cleanChunk)
	buf.WriteByte(']')

	var records []models.NDJsonRecord

	if err := json.Unmarshal(buf.Bytes(), &records); err != nil {
		return nil, buf, err
	}

	return records, buf, nil
}
