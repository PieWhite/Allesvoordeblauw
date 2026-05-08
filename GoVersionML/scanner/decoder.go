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

	var tmp []netflowRecordNoEasyJSON
	if err := json.Unmarshal(buf.Bytes(), &tmp); err != nil {
		return buf, err
	}
	if len(tmp) > 0 {
		*recordsPtr = appendNetflowRecordSlice(*recordsPtr, tmp)
	}

	return buf, nil
}
