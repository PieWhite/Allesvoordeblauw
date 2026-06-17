package pipeline

import "io"

type ProgressStage string

const (
	ProgressBytesRead         ProgressStage = "bytes_read"
	ProgressRecordsDecoded    ProgressStage = "records_decoded"
	ProgressRecordsAggregated ProgressStage = "records_aggregated"
	ProgressWindowsInferred   ProgressStage = "windows_inferred"
)

type ProgressEvent struct {
	Stage ProgressStage
	Delta int64
	File  string
}

var OnProgress func(bytesRead int64)
var OnProgressEvent func(event ProgressEvent)

type ProgressReader struct {
	r          io.Reader
	OnProgress func(int64)
	Path       string
}

func (pr *ProgressReader) Read(p []byte) (n int, err error) {
	n, err = pr.r.Read(p)
	if n > 0 {
		if pr.OnProgress != nil {
			pr.OnProgress(int64(n))
		}
		if OnProgressEvent != nil {
			OnProgressEvent(ProgressEvent{
				Stage: ProgressBytesRead,
				Delta: int64(n),
				File:  pr.Path,
			})
		}
	}
	return n, err
}
