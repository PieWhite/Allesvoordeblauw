package JSONScanner

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

func decodeChunkArray(chunk []byte, recordsPtr *[]models.NetflowRecord) (*bytes.Buffer, error) {
	cleanChunk := bytes.Trim(bytes.TrimSpace(chunk), "[], \n\r\t")
	if len(cleanChunk) == 0 {
		return nil, nil
	}

	buf := wrapPool.Get().(*bytes.Buffer)
	buf.Reset()
	buf.Grow(len(cleanChunk) + 2)
	buf.WriteByte('[')
	buf.Write(cleanChunk)
	buf.WriteByte(']')

	if err := json.Unmarshal(buf.Bytes(), recordsPtr); err != nil {
		return buf, err
	}

	return buf, nil
}
